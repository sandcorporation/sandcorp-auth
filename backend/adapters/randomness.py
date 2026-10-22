"""Randomness adapter: the one place services ask for random bytes (tokens, codes, salts).

Tests swap in a deterministic source with `set_randomness()`.
"""

import secrets
from typing import Protocol


class Randomness(Protocol):
    def token_bytes(self, n: int) -> bytes: ...


class SystemRandomness:
    def token_bytes(self, n: int) -> bytes:
        return secrets.token_bytes(n)


_randomness: Randomness = SystemRandomness()


def get_randomness() -> Randomness:
    return _randomness


def set_randomness(randomness: Randomness) -> Randomness:
    """Install `randomness` and return the previous one so callers can restore it."""
    global _randomness
    previous, _randomness = _randomness, randomness
    return previous
