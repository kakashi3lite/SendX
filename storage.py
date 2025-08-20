"""
storage.py
============

Pluggable storage backends for the One‑View Secrets application.

This module defines a simple abstraction for storing and retrieving secrets,
along with two concrete implementations:

* ``MemoryStorage`` – an in‑memory dictionary suitable for development or testing.
* ``KvStorage`` – a placeholder for a future Replit KV implementation.  In
  production on Replit you should replace this class with one that wraps
  ``replit.db`` or another persistent KV store.

Both backends implement an identical interface exposing three methods:

* ``put(id, record)`` – store a new secret record with a time‑to‑live (TTL).
* ``get_once(id)`` – atomically retrieve and remove a secret record.  This
  ensures one‑time access semantics.  ``MemoryStorage`` emulates atomicity
  through a tombstone pattern; a future ``KvStorage`` should provide a
  truly atomic ``GETDEL`` operation when supported by the underlying store.
* ``ttl(id)`` – return the remaining TTL in seconds or ``None`` if the key
  does not exist.  This is used to surface expiry information without
  exposing the ciphertext.

The ``SecretRecord`` TypedDict enumerates the fields stored for each
secret.  Storing additional metadata is possible but beyond the scope of
this project.
"""

from __future__ import annotations

import time
import json
from abc import ABC, abstractmethod
from typing import Optional, TypedDict


class SecretRecord(TypedDict, total=False):
    """Representation of a stored secret.

    ``ciphertext``
        Base64‑encoded ciphertext that can only be decrypted client side.

    ``iv``
        Optional initialisation vector for AES‑GCM.  Included for
        completeness although the current front‑end bundles the IV into the
        ciphertext payload.

    ``exp``
        Expiration timestamp in seconds since the epoch.  Once the current
        time passes ``exp``, the secret is considered expired and should
        return ``None``.

    ``consumed``
        Boolean flag indicating whether the secret has been accessed.  This
        guards against multiple reads in the absence of an atomic get–delete
        primitive.
    """

    ciphertext: str
    iv: Optional[str]
    exp: int
    consumed: bool


class Storage(ABC):
    """Abstract base class for secret storage backends."""

    @abstractmethod
    async def put(self, id: str, rec: SecretRecord) -> None:
        """Store a secret record under ``id``.

        The implementation must overwrite existing entries.  The TTL is
        encoded in ``rec['exp']`` and should be honoured.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_once(self, id: str) -> Optional[SecretRecord]:
        """Atomically retrieve and delete a secret record.

        If the record is found and has not yet expired, mark it as
        consumed and remove it from the store so that subsequent calls
        return ``None``.  If the record does not exist, has expired or has
        already been consumed, return ``None``.
        """
        raise NotImplementedError

    @abstractmethod
    async def ttl(self, id: str) -> Optional[int]:
        """Return the remaining time to live for ``id`` in seconds.

        Returns ``None`` if the key does not exist or has expired.
        """
        raise NotImplementedError


class MemoryStorage(Storage):
    """In‑memory implementation of ``Storage``.

    This backend is intended for development and testing.  It stores
    everything in a process‑local dictionary.  Atomicity is simulated
    through a simple tombstone pattern; true atomicity requires a
    concurrent key–value store such as Redis.
    """

    def __init__(self) -> None:
        self._store: dict[str, SecretRecord] = {}

    async def put(self, id: str, rec: SecretRecord) -> None:
        self._store[id] = rec

    async def get_once(self, id: str) -> Optional[SecretRecord]:
        record = self._store.get(id)
        if not record:
            return None
        now = int(time.time())
        if now > record["exp"]:
            # expired
            self._store.pop(id, None)
            return None
        if record.get("consumed", False):
            return None
        # mark as consumed and delete to simulate atomic get–delete
        record["consumed"] = True
        # remove from store to enforce one‑time retrieval
        self._store.pop(id, None)
        return record

    async def ttl(self, id: str) -> Optional[int]:
        record = self._store.get(id)
        if not record:
            return None
        now = int(time.time())
        remaining = record["exp"] - now
        return max(0, remaining) if remaining > 0 else None


class KvStorage(Storage):
    """Stub implementation for a future Replit KV backend.

    Replit's key–value store does not currently support atomic get–delete
    operations.  This class exists to illustrate how the interface could be
    extended in the future.  To use it, provide an instance of a KV client
    that supports ``get``, ``set``, ``delete`` and optionally ``ttl``.
    """

    def __init__(self, kv_client: Any, prefix: str = "sec:") -> None:
        self.kv = kv_client
        self.prefix = prefix

    def _key(self, id: str) -> str:
        return f"{self.prefix}{id}"

    async def put(self, id: str, rec: SecretRecord) -> None:
        # KV stores typically accept JSON serialisable values
        await self.kv.set(self._key(id), json.dumps(rec))
        ttl_seconds = rec["exp"] - int(time.time())
        if ttl_seconds > 0:
            await self.kv.expire(self._key(id), ttl_seconds)

    async def get_once(self, id: str) -> Optional[SecretRecord]:
        # Without native GETDEL we emulate atomicity with a tombstone flag
        raw = await self.kv.get(self._key(id))
        if not raw:
            return None
        try:
            record: SecretRecord = json.loads(raw)
        except json.JSONDecodeError:
            # corrupted record
            await self.kv.delete(self._key(id))
            return None
        now = int(time.time())
        if now > record["exp"]:
            await self.kv.delete(self._key(id))
            return None
        if record.get("consumed", False):
            await self.kv.delete(self._key(id))
            return None
        # mark consumed and update store
        record["consumed"] = True
        await self.kv.set(self._key(id), json.dumps(record))
        # In the absence of GETDEL we return the record but leave a tombstone
        # behind.  A background job should periodically purge consumed keys.
        return record

    async def ttl(self, id: str) -> Optional[int]:
        # Many KV stores provide TTL retrieval
        ttl = await self.kv.ttl(self._key(id))
        return ttl if ttl and ttl > 0 else None