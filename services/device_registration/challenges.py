from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

CHALLENGE_PREFIX = "device-registration:challenge:"
CHALLENGE_AUDIENCE = "marty-device-registration"
_CONSUME_SCRIPT = """
local current = redis.call('GET', KEYS[1])
if not current or current ~= ARGV[1] then
  return 0
end
redis.call('DEL', KEYS[1])
return 1
"""


@dataclass(frozen=True)
class ChallengeRecord:
    challenge_id: str
    user_id: str
    device_id: str
    public_key_kid: str
    public_key_sha256: str
    nonce: str
    created_at: str
    expires_at: str
    registration_id: str | None = None
    key_version: int | None = None
    purpose: str = "device_registration"
    audience: str = CHALLENGE_AUDIENCE
    message_version: int = 2

    def message(self) -> bytes:
        from device_registration.native import challenge_message

        return challenge_message(self)

    def encoded_message(self) -> str:
        from device_registration.native import encoded_challenge_message

        return encoded_challenge_message(self)

    def is_expired(self, now: datetime | None = None) -> bool:
        from device_registration.native import challenge_is_expired

        return challenge_is_expired(self, now)


class ChallengeStore:
    def __init__(self, redis_client: Any | None, ttl_seconds: int) -> None:
        self._redis = redis_client
        self._ttl_seconds = ttl_seconds
        self._fallback: dict[str, str] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _serialize(record: ChallengeRecord) -> str:
        return json.dumps(asdict(record), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _deserialize(raw: str | bytes) -> ChallengeRecord:
        if isinstance(raw, bytes):
            raw = raw.decode()
        payload = json.loads(raw)
        if "message_version" not in payload:
            payload["message_version"] = 1
        return ChallengeRecord(**payload)

    async def issue(
        self,
        user_id: str,
        device_id: str,
        public_key_kid: str,
        public_key_sha256: str,
        *,
        registration_id: str | None = None,
        key_version: int | None = None,
        purpose: str = "device_registration",
        audience: str = CHALLENGE_AUDIENCE,
    ) -> ChallengeRecord:
        now = datetime.now(timezone.utc)
        for _attempt in range(4):
            record = ChallengeRecord(
                challenge_id=secrets.token_urlsafe(24),
                user_id=user_id,
                device_id=device_id,
                public_key_kid=public_key_kid,
                public_key_sha256=public_key_sha256,
                nonce=secrets.token_urlsafe(32),
                created_at=now.isoformat(),
                expires_at=(now + timedelta(seconds=self._ttl_seconds)).isoformat(),
                registration_id=registration_id,
                key_version=key_version,
                purpose=purpose,
                audience=audience,
            )
            serialized = self._serialize(record)
            key = f"{CHALLENGE_PREFIX}{record.challenge_id}"
            if self._redis is not None:
                created = await self._redis.set(
                    key,
                    serialized,
                    ex=self._ttl_seconds,
                    nx=True,
                )
                if created:
                    return record
            else:
                async with self._lock:
                    if record.challenge_id not in self._fallback:
                        self._fallback[record.challenge_id] = serialized
                        return record
        raise RuntimeError("Could not allocate a unique device challenge")

    async def get(self, challenge_id: str) -> ChallengeRecord | None:
        key = f"{CHALLENGE_PREFIX}{challenge_id}"
        if self._redis is not None:
            raw = await self._redis.get(key)
        else:
            async with self._lock:
                raw = self._fallback.get(challenge_id)
        if raw is None:
            return None
        record = self._deserialize(raw)
        if record.is_expired():
            await self.consume(record)
            return None
        return record

    async def consume(self, record: ChallengeRecord) -> bool:
        key = f"{CHALLENGE_PREFIX}{record.challenge_id}"
        expected = self._serialize(record)
        if self._redis is not None:
            result = await self._redis.eval(_CONSUME_SCRIPT, 1, key, expected)
            return bool(result)
        async with self._lock:
            if self._fallback.get(record.challenge_id) != expected:
                return False
            del self._fallback[record.challenge_id]
            return True

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
