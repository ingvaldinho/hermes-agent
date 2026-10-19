"""Restricted Telegram approval ingress used before any gateway session exists.

The module deliberately has no dependency on the agent runtime.  It recognizes only
an exact approval decision and sends a small authenticated event to a local Unix
socket.  Decision-like malformed text is consumed locally instead of falling through
to the general transcript.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import stat
import struct
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

APPROVAL_STATES = (
    "CREATED", "WAITING_APPROVAL", "APPROVED_PENDING_RESUME", "REFUSED", "EXPIRED",
    "EXECUTION_CLAIMED", "RESULT_RECORDED", "NEEDS_RECONCILE", "BLOCKED",
    "RESULT_DELIVERED", "COMPLETE",
)
DECISION_RE = re.compile(r"(APPROUVER|REFUSER) ([A-Za-z0-9][A-Za-z0-9._:-]{0,127})")
MAX_EVENT_BYTES = 4096
MAX_RESPONSE_BYTES = 2048
MAX_UNIX_PATH_BYTES = 107
_DECISION_WORDS = ("APPROUVER", "REFUSER")
# Only used to quarantine command-shaped lookalikes.  Exact decisions are always
# matched against the original bytes above; attacker input is never normalized
# into an accepted command.
_CONFUSABLES = str.maketrans({
    "0": "O", "1": "I", "3": "E", "4": "A", "5": "S", "7": "T",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "а": "A", "е": "E", "о": "O", "р": "P", "с": "C", "у": "Y", "х": "X",
})


@dataclass(frozen=True)
class IngressResult:
    consumed: bool
    accepted: bool = False
    acknowledgement: str = ""
    uncertain: bool = False


def _one_edit_or_less(left: str, right: str) -> bool:
    """Return whether two short strings differ by at most one edit."""
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) > len(right):
        left, right = right, left
    index = errors = offset = 0
    while index < len(left):
        if left[index] == right[index + offset]:
            index += 1
            continue
        errors += 1
        if errors > 1:
            return False
        if len(left) == len(right):
            index += 1
        else:
            offset = 1
    return True


def _decision_like(text: str) -> bool:
    """Recognize a command-shaped approval lookalike without accepting it.

    Telegram routes slash-prefixed variants through a different handler, and malformed
    attacker input may use punctuation, zero-width characters, accents or common
    homoglyphs.  Collapse only the leading command-shaped run; ordinary prose that
    mentions a decision word later remains ordinary input.
    """
    lead = text.lstrip()
    if not lead:
        return False
    if lead.startswith("/"):
        lead = lead[1:]
    normalized = unicodedata.normalize("NFKD", lead).translate(_CONFUSABLES).upper()
    normalized = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    compact = ""
    for ch in normalized[:32]:
        if ch.isalnum():
            compact += ch
            if len(compact) >= 12:
                break
        elif compact and ch.isspace():
            # Spaces can either terminate the command or disguise it as separated letters.
            continue
        elif compact:
            continue
    if not compact:
        return False
    return any(
        compact.startswith(word)
        # Include the one-short prefix: when the command itself loses a character
        # (``APROUVER ref``), compacting also appends the reference's first byte.
        or any(
            _one_edit_or_less(compact[:width], word)
            for width in (len(word) - 1, len(word), len(word) + 1)
        )
        for word in _DECISION_WORDS
    )


def classify_decision_text(text: Any) -> tuple[bool, re.Match[str] | None]:
    """Return ``(decision_like, exact_match)`` without normalizing accepted input."""
    if not isinstance(text, str):
        return False, None
    match = DECISION_RE.fullmatch(text)
    return match is not None or _decision_like(text), match


def _peer_uid(sock: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise OSError("Unix peer credentials are unavailable")
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def _sender_uid(ancillary: list[tuple[int, int, bytes]], flags: int) -> int:
    """Authenticate the process that sent a response chunk, not the listener creator."""
    if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
        raise OSError("approval ingress response or credentials truncated")
    credentials = [value for level, kind, value in ancillary
                   if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
    if len(credentials) != 1 or len(credentials[0]) != struct.calcsize("3i"):
        raise PermissionError("approval ingress response credentials missing")
    _pid, uid, _gid = struct.unpack("3i", credentials[0])
    return uid


def _read_attested_line(sock: socket.socket, expected_sender_uid: int,
                        deadline: float, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("approval ingress deadline exceeded")
        sock.settimeout(remaining)
        chunk, ancillary, flags, _address = sock.recvmsg(
            min(512, limit + 1 - total), socket.CMSG_SPACE(struct.calcsize("3i")),
        )
        if not chunk:
            raise OSError("truncated approval ingress message")
        if _sender_uid(ancillary, flags) != expected_sender_uid:
            raise PermissionError("approval ingress response sender uid mismatch")
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise ValueError("approval ingress response exceeds size limit")
        if b"\n" in chunk:
            raw = b"".join(chunks)
            if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
                raise ValueError("malformed approval ingress response framing")
            return raw[:-1]


def _exchange(
    path: str,
    expected_peer_uid: int,
    payload: bytes,
    timeout: float,
    expected_socket_uid: int | None = None,
    expected_socket_gid: int | None = None,
) -> dict[str, Any]:
    if len(payload) > MAX_EVENT_BYTES:
        raise ValueError("approval event exceeds size limit")
    if not isinstance(path, str) or not path or "\x00" in path or not os.path.isabs(path):
        raise ValueError("approval ingress path must be an absolute filesystem path")
    if len(os.fsencode(path)) > MAX_UNIX_PATH_BYTES:
        raise ValueError("approval ingress path exceeds Unix socket limit")
    if os.path.realpath(path) != os.path.abspath(path):
        raise ValueError("approval ingress path may not traverse symlinks")
    expected_peer_uid = int(expected_peer_uid)
    if expected_peer_uid == os.geteuid():
        raise PermissionError("approval ingress bridge uid must differ from gateway uid")
    socket_uid = expected_peer_uid if expected_socket_uid is None else int(expected_socket_uid)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
        raise ValueError("approval ingress path is not a Unix socket")
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != socket_uid or mode & 0o007:
        raise PermissionError("approval ingress socket ownership or mode mismatch")
    if mode & 0o070:
        if expected_socket_gid is None or info.st_gid != int(expected_socket_gid) or mode != 0o660:
            raise PermissionError("approval ingress group socket ownership or mode mismatch")
    elif mode != 0o600:
        raise PermissionError("approval ingress private socket mode mismatch")
    deadline = time.monotonic() + max(0.05, float(timeout))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        sock.connect(path)
        # With a systemd-inherited listener, SO_PEERCRED identifies systemd at
        # listen(2), while SCM_CREDENTIALS identifies the process sending data.
        if _peer_uid(sock) != socket_uid:
            raise PermissionError("approval ingress listener uid mismatch")
        if not hasattr(socket, "SO_PASSCRED") or not hasattr(socket, "SCM_CREDENTIALS"):
            raise OSError("Unix sender credentials are unavailable")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        greeting = _read_attested_line(sock, expected_peer_uid, deadline, 16)
        if greeting == b"DENIED":
            return {"accepted": False, "acknowledgement": "Décision refusée."}
        if greeting != b"READY":
            raise ValueError("approval ingress greeting mismatch")
        sock.sendall(payload + b"\n")
        raw = _read_attested_line(sock, expected_peer_uid, deadline, MAX_RESPONSE_BYTES)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict) or set(value) - {"accepted", "acknowledgement", "uncertain"}:
            raise ValueError("malformed approval ingress response")
        return value
    finally:
        sock.close()


async def handle_telegram_decision(
    *, text: Any, chat_id: Any, author_id: Any, event_id: Any, timestamp: datetime | None,
    socket_path: str | None, expected_peer_uid: int | None,
    expected_socket_uid: int | None = None, expected_socket_gid: int | None = None,
    timeout: float = 2.0,
) -> IngressResult:
    """Consume an approval-looking Telegram message before batching/session creation.

    Missing configuration fails closed for decision-like messages.  A transport timeout
    is ambiguous, so the acknowledgement says reconciliation is required and the text
    is never exposed to the general agent.
    """
    decision_like, match = classify_decision_text(text)
    if not decision_like:
        return IngressResult(consumed=False)
    if match is None:
        return IngressResult(True, False, "Décision refusée : format exact requis.")
    if not socket_path or expected_peer_uid is None:
        return IngressResult(True, False, "Décision non enregistrée : ingress indisponible.")
    if not all(str(value or "").strip() for value in (chat_id, author_id, event_id)):
        return IngressResult(True, False, "Décision refusée : identité incomplète.")
    observed = timestamp if isinstance(timestamp, datetime) else datetime.now(timezone.utc)
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    event = {
        "platform": "telegram",
        "chat_id": str(chat_id),
        "author_id": str(author_id),
        "event_id": str(event_id),
        "text": text,
        "timestamp": observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(
                _exchange, socket_path, int(expected_peer_uid), payload, float(timeout),
                expected_socket_uid, expected_socket_gid,
            ),
            timeout=max(0.05, float(timeout) + 0.25),
        )
    except (asyncio.TimeoutError, TimeoutError, OSError, ValueError, PermissionError):
        return IngressResult(
            True, False,
            "Issue de décision incertaine : aucune exécution ne sera lancée; réconciliation requise.",
            True,
        )
    accepted = response.get("accepted") is True
    acknowledgement = str(response.get("acknowledgement") or (
        "Décision enregistrée; reprise Slack authentifiée requise."
        if accepted else "Décision refusée."
    ))[:512]
    return IngressResult(True, accepted, acknowledgement, response.get("uncertain") is True)
