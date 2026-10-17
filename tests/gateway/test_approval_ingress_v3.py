import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.approval_ingress import (
    APPROVAL_STATES,
    IngressResult,
    classify_decision_text,
    handle_telegram_decision,
)
from gateway.config import Platform, PlatformConfig

EXPECTED_STATES = (
    "CREATED", "WAITING_APPROVAL", "APPROVED_PENDING_RESUME", "REFUSED", "EXPIRED",
    "EXECUTION_CLAIMED", "RESULT_RECORDED", "NEEDS_RECONCILE", "BLOCKED",
    "RESULT_DELIVERED", "COMPLETE",
)


@pytest.fixture
def approval_socket_path():
    """Allocate short, unique socket names inside the approved artifact tree."""
    artifact_root = Path(__file__).resolve().parents[2] / ".test-artifacts"
    artifact_root.mkdir(parents=True, exist_ok=True)
    created = []

    def allocate():
        fd, name = tempfile.mkstemp(prefix="ai-", suffix=".s", dir=artifact_root)
        os.close(fd)
        path = Path(name)
        path.unlink()
        assert len(os.fsencode(path)) <= 107
        created.append(path)
        return path

    yield allocate
    for path in created:
        path.unlink(missing_ok=True)


def test_exact_parser_and_shared_states():
    assert APPROVAL_STATES == EXPECTED_STATES
    assert classify_decision_text("APPROUVER ref-1")[1] is not None
    assert classify_decision_text("REFUSER ref_1")[1] is not None
    for malformed in (
        "APPROUVER", "APPROUVER  ref", "APPROUVER ref extra", " approuver ref",
        "approuver ref", "REFUSER ref\n", "/APPROUVER ref", "APPROUVER:ref",
        "APPR0UVER ref", "APPROU\u200bVER ref", "APROUVER ref", "RÉFUSER ref",
        "R E F U S E R ref", "РEFUSER ref",
    ):
        decision_like, match = classify_decision_text(malformed)
        assert decision_like is True
        assert match is None
    assert classify_decision_text("ordinary message") == (False, None)
    for ordinary in ("please APPROUVER ref", "we should REFUSER that", "approval reference"):
        assert classify_decision_text(ordinary) == (False, None)


@pytest.mark.asyncio
async def test_malformed_and_unconfigured_decisions_are_consumed_without_transport():
    malformed = await handle_telegram_decision(
        text="APPROUVER  bad", chat_id="1", author_id="2", event_id="3",
        timestamp=None, socket_path=None, expected_peer_uid=None,
    )
    assert malformed.consumed and not malformed.accepted
    unavailable = await handle_telegram_decision(
        text="APPROUVER ref", chat_id="1", author_id="2", event_id="3",
        timestamp=None, socket_path=None, expected_peer_uid=None,
    )
    assert unavailable.consumed and not unavailable.accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("text", (
    "APROUVER ref", "APPR0UVER ref", "APPROU\u200bVER ref", "RÉFUSER ref",
    "R E F U S E R ref", "РEFUSER ref",
))
async def test_malformed_lookalikes_are_quarantined_never_accepted(text):
    result = await handle_telegram_decision(
        text=text, chat_id="1", author_id="2", event_id="3",
        timestamp=None, socket_path=None, expected_peer_uid=None,
    )
    assert result.consumed and not result.accepted and not result.uncertain


@pytest.mark.asyncio
async def test_gateway_uid_cannot_be_configured_as_bridge_uid(tmp_path):
    result = await handle_telegram_decision(
        text="APPROUVER ref", chat_id="1", author_id="2", event_id="3",
        timestamp=None, socket_path=str(tmp_path / "missing.sock"),
        expected_peer_uid=os.geteuid(), expected_socket_uid=os.geteuid(),
    )
    assert result.consumed and result.uncertain and not result.accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("mode, gid_offset", ((0o666, 0), (0o660, 1)))
async def test_systemd_socket_mode_and_group_are_verified(approval_socket_path, mode, gid_offset):
    path = approval_socket_path()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, mode)
    try:
        result = await handle_telegram_decision(
            text="APPROUVER ref", chat_id="1", author_id="2", event_id="3",
            timestamp=None, socket_path=str(path), expected_peer_uid=os.geteuid() + 1,
            expected_socket_uid=os.geteuid(), expected_socket_gid=os.getegid() + gid_offset,
        )
    finally:
        server.close()
    assert result.consumed and result.uncertain and not result.accepted


def _start_server(path, response, captured, *, drip=False, mode=0o660):
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        os.chmod(path, mode)
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
            if hasattr(socket, "SO_PEERCRED"):
                raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                captured["peer_uid"] = struct.unpack("3i", raw)[1]
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
                    threading.Event().wait(0.05)
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


def _finish_server(thread, failures):
    thread.join(3)
    assert not thread.is_alive(), "approval test server did not stop within its bound"
    if failures:
        raise failures[0]


@pytest.mark.asyncio
async def test_local_transport_is_bounded_and_peer_authenticated(approval_socket_path, monkeypatch):
    path = approval_socket_path()
    captured = {}
    bridge_uid = os.geteuid() + 1
    monkeypatch.setattr("gateway.approval_ingress._peer_uid", lambda sock: bridge_uid)
    thread, failures = _start_server(
        path, {"accepted": True, "acknowledgement": "stored"}, captured)
    try:
        result = await handle_telegram_decision(
            text="APPROUVER ref-1", chat_id="10", author_id="20", event_id="30",
            timestamp=datetime(2026, 10, 15, tzinfo=timezone.utc), socket_path=str(path),
            expected_peer_uid=bridge_uid, expected_socket_uid=os.geteuid(),
            expected_socket_gid=os.getegid(), timeout=1,
        )
    finally:
        _finish_server(thread, failures)
    assert result == IngressResult(True, True, "stored", False)
    assert captured["event"] == {
        "platform": "telegram", "chat_id": "10", "author_id": "20", "event_id": "30",
        "text": "APPROUVER ref-1", "timestamp": "2026-10-15T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_wrong_peer_uid_and_slow_drip_are_uncertain(approval_socket_path, monkeypatch):
    bridge_uid = os.geteuid() + 1
    for index, (drip, timeout) in enumerate(((False, 1), (True, 0.1))):
        if drip:
            monkeypatch.setattr("gateway.approval_ingress._peer_uid", lambda sock: bridge_uid)
        path = approval_socket_path()
        captured = {}
        thread, failures = _start_server(path, {"accepted": True}, captured, drip=drip)
        try:
            result = await handle_telegram_decision(
                text="APPROUVER ref", chat_id="1", author_id="2", event_id=str(index),
                timestamp=None, socket_path=str(path), expected_peer_uid=bridge_uid,
                expected_socket_uid=os.geteuid(), expected_socket_gid=os.getegid(), timeout=timeout,
            )
        finally:
            _finish_server(thread, failures)
        assert result.consumed and result.uncertain and not result.accepted


def _adapter():
    from plugins.platforms.telegram.adapter import TelegramAdapter

    adapter = object.__new__(TelegramAdapter)
    adapter.platform = Platform.TELEGRAM
    adapter.config = PlatformConfig(enabled=True, token="fake", extra={})
    adapter._message_handler = AsyncMock()
    adapter._pending_text_batches = {}
    adapter._pending_text_batch_tasks = {}
    adapter._text_batch_delay_seconds = 0.01
    adapter._text_batch_split_delay_seconds = 0.01
    adapter._mention_patterns = []
    adapter._forum_lock = asyncio.Lock()
    adapter._forum_command_registered = set()
    adapter._active_sessions = {}
    adapter._pending_messages = {}
    adapter._is_user_authorized_from_message = lambda msg: True
    adapter._gate_or_observe = lambda *args: (_ for _ in ()).throw(AssertionError("gate reached"))
    return adapter


@pytest.mark.asyncio
async def test_adapter_barrier_runs_after_auth_and_before_event_or_session(monkeypatch):
    adapter = _adapter()
    reply = AsyncMock()
    msg = SimpleNamespace(
        text="APPROUVER ref", chat=SimpleNamespace(id=1), from_user=SimpleNamespace(id=2),
        date=None, reply_text=reply,
    )
    update = SimpleNamespace(update_id=3, message=msg, effective_message=None)
    called = []

    async def fake_ingress(**kwargs):
        called.append(kwargs)
        return IngressResult(True, True, "recorded")

    monkeypatch.setattr("gateway.approval_ingress.handle_telegram_decision", fake_ingress)
    adapter._build_triggered_event = AsyncMock(side_effect=AssertionError("event built"))
    adapter._enqueue_text_event = lambda event: (_ for _ in ()).throw(AssertionError("session path"))
    await adapter._handle_text_message(update, SimpleNamespace())
    assert len(called) == 1
    reply.assert_awaited_once_with("recorded")
    adapter._message_handler.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("text", (
    "APPROUVER", "APPROUVER:ref", "APPR0UVER ref", "APPROU\u200bVER ref",
    "APROUVER ref", "RÉFUSER ref", "R E F U S E R ref",
))
async def test_malformed_approval_like_text_never_reaches_general_path(text):
    adapter = _adapter()
    reply = AsyncMock()
    msg = SimpleNamespace(
        text=text, chat=SimpleNamespace(id=1), from_user=SimpleNamespace(id=2),
        date=None, reply_text=reply,
    )
    await adapter._handle_text_message(
        SimpleNamespace(update_id=3, message=msg, effective_message=None), SimpleNamespace())
    reply.assert_awaited_once()


@pytest.mark.asyncio
async def test_slash_approval_lookalike_is_barred_on_command_path():
    adapter = _adapter()
    adapter._should_process_message = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("command gate reached"))
    reply = AsyncMock()
    msg = SimpleNamespace(
        text="/APPROUVER ref", chat=SimpleNamespace(id=1), from_user=SimpleNamespace(id=2),
        date=None, reply_text=reply,
    )
    await adapter._handle_command(
        SimpleNamespace(update_id=3, message=msg, effective_message=None), SimpleNamespace())
    reply.assert_awaited_once()


@pytest.mark.asyncio
async def test_unauthorized_decision_never_reaches_ingress(monkeypatch):
    adapter = _adapter()
    adapter._is_user_authorized_from_message = lambda msg: False
    adapter._log_blocked_user = lambda msg: None
    ingress = AsyncMock()
    monkeypatch.setattr("gateway.approval_ingress.handle_telegram_decision", ingress)
    msg = SimpleNamespace(text="APPROUVER ref")
    await adapter._handle_text_message(SimpleNamespace(update_id=1, message=msg, effective_message=None), SimpleNamespace())
    ingress.assert_not_awaited()
