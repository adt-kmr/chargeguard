"""
Backend registry: lets callers pick a TPM backend or verifier by name.

    from attestation import get_backend
    with get_backend("software") as tpm:
        quote = tpm.quote(nonce, PCRSelection())
"""
from __future__ import annotations

from typing import Callable, TypeVar

from .base import BackendUnavailable, TPMBackend, Verifier
from .config import AttestationConfig

_BACKENDS: dict[str, type[TPMBackend]] = {}
_VERIFIERS: dict[str, type[Verifier]] = {}

B = TypeVar("B", bound=type[TPMBackend])
V = TypeVar("V", bound=type[Verifier])


def register_backend(name: str) -> Callable[[B], B]:
    def deco(cls: B) -> B:
        cls.name = name
        _BACKENDS[name] = cls
        return cls
    return deco


def register_verifier(name: str) -> Callable[[V], V]:
    def deco(cls: V) -> V:
        cls.name = name
        _VERIFIERS[name] = cls
        return cls
    return deco


def available_backends() -> dict[str, bool]:
    """Registered backend names mapped to whether their dependencies are present."""
    return {name: cls.is_available() for name, cls in _BACKENDS.items()}


def available_verifiers() -> list[str]:
    return sorted(_VERIFIERS)


def get_backend(name: str | None = None, config: AttestationConfig | None = None, **kwargs) -> TPMBackend:
    config = config or AttestationConfig()
    name = name or config.backend
    try:
        cls = _BACKENDS[name]
    except KeyError:
        raise ValueError(f"Unknown TPM backend '{name}'. Registered: {sorted(_BACKENDS)}") from None
    if not cls.is_available():
        raise BackendUnavailable(f"TPM backend '{name}' is registered but its dependencies are missing.")
    return cls(config=config, **kwargs)


def get_verifier(name: str = "local", config: AttestationConfig | None = None, **kwargs) -> Verifier:
    config = config or AttestationConfig()
    try:
        cls = _VERIFIERS[name]
    except KeyError:
        raise ValueError(f"Unknown verifier '{name}'. Registered: {sorted(_VERIFIERS)}") from None
    return cls(config=config, **kwargs)
