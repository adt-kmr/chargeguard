"""
Keylime verifier adapter.

Keylime (vendor/tpm/keylime) runs continuous remote attestation: a
registrar enrols agents' EK/AK, and a verifier polls each agent for quotes
and IMA / measured-boot logs. ChargeGuard does not drive that loop itself;
it asks the Keylime verifier for an agent's current operational state and
maps it to an AttestationResult.

Agent identity: pass `evidence.metadata["keylime_agent_uuid"]`, or the
device_id is used as the agent UUID.

Uses only the standard library (urllib) with optional mutual TLS, matching
the verifier's default deployment.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

from ..base import Verifier
from ..config import AttestationConfig
from ..registry import register_verifier
from ..types import AttestationEvidence, AttestationResult, AttestationStatus, EndorsementKey

# Keylime operational_state codes (keylime/common/states.py)
_TRUSTED_STATES = {3: "GET_QUOTE", 4: "GET_QUOTE_RETRY", 5: "PROVIDE_V", 6: "PROVIDE_V_RETRY"}
_FAILED_STATES = {7: "FAILED", 9: "INVALID_QUOTE", 10: "TENANT_FAILED"}


@register_verifier("keylime")
class KeylimeVerifier(Verifier):
    def __init__(self, config: AttestationConfig | None = None, opener=None):
        self.config = config or AttestationConfig()
        self._opener = opener            # injectable for tests

    def _ssl_context(self) -> ssl.SSLContext | None:
        c = self.config
        if not c.keylime_verifier_url.startswith("https"):
            return None
        ctx = ssl.create_default_context(cafile=c.keylime_ca_cert)
        if c.keylime_client_cert:
            ctx.load_cert_chain(c.keylime_client_cert, c.keylime_client_key)
        return ctx

    def agent_status(self, agent_uuid: str) -> dict:
        c = self.config
        url = f"{c.keylime_verifier_url.rstrip('/')}/v{c.keylime_api_version}/agents/{agent_uuid}"
        if self._opener:
            return self._opener(url)
        with urllib.request.urlopen(url, timeout=c.keylime_timeout_s, context=self._ssl_context()) as r:
            return json.loads(r.read().decode())

    def verify(self, evidence: AttestationEvidence, expected_nonce: bytes,
               trusted_key: EndorsementKey | None = None,
               golden_pcrs: dict[int, bytes] | None = None) -> AttestationResult:
        # Keylime issues its own nonces and holds the golden policy, so
        # expected_nonce / trusted_key / golden_pcrs are not used here.
        agent = evidence.metadata.get("keylime_agent_uuid", evidence.device_id)
        try:
            body = self.agent_status(agent)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return AttestationResult(AttestationStatus.UNTRUSTED,
                                         "Agent not enrolled with Keylime verifier", self.name, {"agent": agent})
            return AttestationResult(AttestationStatus.UNKNOWN, f"Keylime HTTP {e.code}", self.name, {"agent": agent})
        except (urllib.error.URLError, OSError, ValueError) as e:
            return AttestationResult(AttestationStatus.UNKNOWN, f"Keylime unreachable: {e}", self.name, {"agent": agent})

        results = body.get("results", body)
        state = results.get("operational_state")
        details = {"agent": agent, "operational_state": state,
                   "attestation_count": results.get("attestation_count")}
        if state in _TRUSTED_STATES:
            return AttestationResult(AttestationStatus.TRUSTED,
                                     f"Keylime: agent attesting ({_TRUSTED_STATES[state]})", self.name, details)
        if state in _FAILED_STATES:
            details["severity"] = results.get("severity_level")
            details["last_event"] = results.get("last_event_id")
            return AttestationResult(AttestationStatus.UNTRUSTED,
                                     f"Keylime: attestation failed ({_FAILED_STATES[state]})", self.name, details)
        return AttestationResult(AttestationStatus.UNKNOWN,
                                 f"Keylime: agent in transitional state {state}", self.name, details)
