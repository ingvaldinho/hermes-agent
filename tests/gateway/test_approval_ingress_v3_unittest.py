import ast
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock
from datetime import datetime, timezone
from pathlib import Path


from gateway.approval_ingress import APPROVAL_STATES, IngressResult, classify_decision_text, handle_telegram_decision


EXPECTED_STATES = (
    "CREATED", "WAITING_APPROVAL", "APPROVED_PENDING_RESUME", "REFUSED", "EXPIRED",
    "EXECUTION_CLAIMED", "RESULT_RECORDED", "NEEDS_RECONCILE", "BLOCKED",
    "RESULT_DELIVERED", "COMPLETE",
)


_ARTIFACT_ROOT = Path(__file__).resolve().parents[2] / ".test-artifacts"


def short_artifact_path():
    """Return an unused, AF_UNIX-safe path inside the approved artifact tree."""
    _ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="ai-", suffix=".s", dir=_ARTIFACT_ROOT)
    os.close(fd)
    path = Path(name)
    path.unlink()
    if len(os.fsencode(path)) > 107:
        raise AssertionError(f"AF_UNIX test path exceeds 107 bytes: {path}")
    return path


def start_server(path, response, captured, *, drip=False):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        os.chmod(path, 0o660)
        server.listen(1)
        server.settimeout(2)
    except BaseException:
        server.close()
        raise

    failures = []

    def serve():
        conn = None
        try:
            conn, _ = server.accept()
            conn.settimeout(2)
            try:
                conn.sendall(b"READY\n")
            except (BrokenPipeError, ConnectionResetError):
                return
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(512)
                if not chunk:
                    return
                data += chunk
            captured["event"] = json.loads(data[:-1])
            encoded = json.dumps(response).encode() + b"\n"
            if drip:
                for byte in encoded:
                    try:
                        conn.send(bytes([byte]))
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    time.sleep(0.05)
            else:
                conn.sendall(encoded)
        except BaseException as exc:
            failures.append(exc)
        finally:
            if conn is not None:
                conn.close()
            server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    return thread, failures


def finish_server(test_case, thread, failures):
    thread.join(3)
    test_case.assertFalse(thread.is_alive(), "approval test server did not stop within its bound")
    if failures:
        raise failures[0]


class ApprovalIngressTests(unittest.IsolatedAsyncioTestCase):
    def test_exact_parser_and_states(self):
        self.assertEqual(APPROVAL_STATES, EXPECTED_STATES)
        self.assertIsNotNone(classify_decision_text("APPROUVER ref-1")[1])
        for malformed in (
            "APPROUVER", "APPROUVER  ref", " approuver ref", "approuver ref", "REFUSER ref\n",
            "/APPROUVER ref", "APPROUVER:ref", "APPR0UVER ref", "APPROU\u200bVER ref",
            "APROUVER ref", "RÉFUSER ref", "R E F U S E R ref", "РEFUSER ref",
        ):
            decision_like, match = classify_decision_text(malformed)
            self.assertTrue(decision_like)
            self.assertIsNone(match)
        self.assertEqual(classify_decision_text("ordinary"), (False, None))
        for ordinary in ("please APPROUVER ref", "we should REFUSER that", "approval reference"):
            self.assertEqual(classify_decision_text(ordinary), (False, None))

    async def test_malformed_lookalikes_are_quarantined_never_accepted(self):
        for text in (
            "APROUVER ref", "APPR0UVER ref", "APPROU\u200bVER ref", "RÉFUSER ref",
            "R E F U S E R ref", "РEFUSER ref",
        ):
            with self.subTest(text=text):
                result = await handle_telegram_decision(
                    text=text, chat_id="1", author_id="2", event_id="3",
                    timestamp=None, socket_path=None, expected_peer_uid=None)
                self.assertTrue(result.consumed)
                self.assertFalse(result.accepted)
                self.assertFalse(result.uncertain)

    @mock.patch("gateway.approval_ingress._sender_uid", return_value=os.geteuid() + 1)
    async def test_transport_exact_envelope_deadline_and_symlink(self, _sender_uid):
        bridge_uid = os.geteuid() + 1
        path = short_artifact_path()
        self.addCleanup(path.unlink, missing_ok=True)
        captured = {}
        thread, failures = start_server(
            path, {"accepted": True, "acknowledgement": "stored"}, captured)
        try:
            result = await handle_telegram_decision(
                text="APPROUVER ref-1", chat_id="10", author_id="20", event_id="30",
                timestamp=datetime(2026, 10, 15, tzinfo=timezone.utc), socket_path=str(path),
                expected_peer_uid=bridge_uid, expected_socket_uid=os.geteuid(),
                expected_socket_gid=os.getegid(), timeout=1)
        finally:
            finish_server(self, thread, failures)
        self.assertEqual(result, IngressResult(True, True, "stored", False))
        self.assertEqual(captured["event"]["platform"], "telegram")
        self.assertNotIn("scope", captured["event"])

        slow_path = short_artifact_path()
        self.addCleanup(slow_path.unlink, missing_ok=True)
        slow, slow_failures = start_server(slow_path, {"accepted": True}, {}, drip=True)
        started = time.monotonic()
        try:
            uncertain = await handle_telegram_decision(
                text="APPROUVER ref", chat_id="1", author_id="2", event_id="31", timestamp=None,
                socket_path=str(slow_path), expected_peer_uid=bridge_uid,
                expected_socket_uid=os.geteuid(), expected_socket_gid=os.getegid(), timeout=0.1)
            elapsed = time.monotonic() - started
        finally:
            finish_server(self, slow, slow_failures)
        self.assertTrue(uncertain.uncertain)
        self.assertLess(elapsed, 0.5)

        target = short_artifact_path()
        self.addCleanup(target.unlink, missing_ok=True)
        target.write_text("x")
        link = short_artifact_path()
        self.addCleanup(link.unlink, missing_ok=True)
        link.symlink_to(target)
        refused = await handle_telegram_decision(
            text="APPROUVER ref", chat_id="1", author_id="2", event_id="32", timestamp=None,
            socket_path=str(link), expected_peer_uid=bridge_uid,
            expected_socket_uid=os.geteuid(), expected_socket_gid=os.getegid(), timeout=0.1)
        self.assertTrue(refused.uncertain)

    def test_adapter_barrier_is_after_auth_and_before_event_or_session(self):
        adapter_path = Path(__file__).resolve().parents[2] / "plugins/platforms/telegram/adapter.py"
        tree = ast.parse(adapter_path.read_text(encoding="utf-8"))
        method = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.AsyncFunctionDef) and node.name == "_handle_text_message")
        source = ast.get_source_segment(adapter_path.read_text(encoding="utf-8"), method)
        self.assertIsNotNone(source)
        auth = source.index("_is_user_authorized_from_message")
        ingress = source.index("_handle_approval_ingress")
        gate = source.index("if not self._gate_or_observe")
        event = source.index("await self._build_triggered_event")
        self.assertLess(auth, ingress)
        self.assertLess(ingress, gate)
        self.assertLess(ingress, event)
        self.assertIn("if await self._handle_approval_ingress(msg, update):\n            return", source)


if __name__ == "__main__":
    unittest.main()
