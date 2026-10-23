"""
The blue half. A sequence-aware behavioral detector -- the da_bklyn_bridge /
Lineman idea applied to an agentic workflow instead of a radio or a host.

The point it proves: none of Bull Street Bank's per-action controls were wrong. Each
one did its job and passed a legitimately in-policy action. The attack is only
visible across the sequence and at the egress, which is exactly the layer the
per-action controls do not watch. You cannot patch this with a stricter
single-action rule. You detect it or you do not see it at all.

Mapped frameworks:
  NIST AI RMF         -- MEASURE (continuous monitoring), MANAGE (response)
  MITRE ATLAS         -- the exfiltration / impact stages a per-action gate misses
  OWASP LLM           -- Excessive Agency, surfaced behaviorally rather than blocked per-call
"""

from dataclasses import dataclass


@dataclass
class Alert:
    severity: str          # "info" | "warning" | "critical"
    code: str
    message: str


class BehavioralDetector:
    def __init__(self):
        # A learned baseline: which account each known payee label settles to.
        # This is the identity an ordinary monitor builds from history.
        self.payee_identity_baseline = {
            "Vane Management LLC": "VANE-MGMT",
        }
        # Egress destinations the bank's agents are expected to talk to.
        self.egress_allowlist = {
            "telemetry.bull-street-bank.example",
            "updates.bull-street-bank.example",
        }

    def analyze(self, audit, settlement, egress_host, payee_label) -> list[Alert]:
        alerts: list[Alert] = []

        # Signal A: a scheduled payment had its routing corrected this cycle.
        routing_corrected = any(
            e.action == "apply_correction" for e in audit.events
        )

        # Signal B: beneficiary identity drift. The payment carries a known
        # payee label, but it settled to an account that is not that payee's
        # established identity. No single control compares label to destination.
        expected = self.payee_identity_baseline.get(payee_label)
        actual = settlement["destination"]
        identity_drift = expected is not None and actual != expected
        if identity_drift:
            alerts.append(Alert(
                "warning", "BENEFICIARY_IDENTITY_DRIFT",
                f"Payment labeled '{payee_label}' settled to {actual}, but that "
                f"payee's established identity is {expected}.",
            ))

        # Signal C: egress to a destination outside the expected set.
        egress_zone = egress_host.split(".", 1)[1] if "." in egress_host else egress_host
        unrecognized_egress = not any(
            egress_host == a or egress_zone == a or egress_host.endswith("." + a)
            for a in self.egress_allowlist
        )
        if unrecognized_egress:
            alerts.append(Alert(
                "warning", "UNRECOGNIZED_EGRESS",
                f"Confirmation beacon left for {egress_host}, which is not an "
                f"approved egress destination.",
            ))

        # The composite: individually-benign signals, correlated within one
        # workflow cycle, are the thing no per-action control owns.
        if routing_corrected and identity_drift and unrecognized_egress:
            alerts.append(Alert(
                "critical", "AGENTIC_EXFIL_SEQUENCE",
                "Routing correction + beneficiary identity drift + unrecognized "
                "egress in a single cycle. This is a composed, authorized-action "
                "attack. Hold the settlement and open an investigation.",
            ))
        return alerts


def render_alerts(alerts) -> str:
    if not alerts:
        return "  (no alerts)"
    order = {"critical": 0, "warning": 1, "info": 2}
    lines = []
    for a in sorted(alerts, key=lambda x: order.get(x.severity, 9)):
        lines.append(f"  [{a.severity.upper():^8}] {a.code}")
        lines.append(f"            {a.message}")
    return "\n".join(lines)
