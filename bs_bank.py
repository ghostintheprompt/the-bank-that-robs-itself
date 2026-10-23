"""
Bull Street Bank -- a deterministic simulation of an agentic commercial-banking
pipeline, built to demonstrate one structural failure.

The failure: a patient, composed attack in which every individual action is
authorized and maker-checker dual control never fires, because the controls
inspect single actions while the attack lives in pre-existing routing and a
trust transition across a summarization hop.

There is no LLM, no network, and no real institution here. The agents are
rule-based stand-ins that follow the same workflow an LLM agent would: ingest
a document, summarize it to an internal note, reconcile a discrepancy, route
the exception to a checker, apply the approved correction to the core ledger.
Isolating the structural flaw instead of a specific model's jailbreakability
is deliberate. Payloads age. The structure does not.

Mapped frameworks:
  OWASP Top 10 for LLM Applications -- LLM01 Prompt Injection, Excessive Agency
  MITRE ATLAS                        -- AML.T0051 LLM Prompt Injection (indirect)
  NIST AI RMF                        -- MEASURE / MANAGE (monitoring gaps)
Control context (what the chain survives):
  SOX segregation of duties / maker-checker dual control
  FFIEC authentication and transaction-monitoring expectations
  BSA/AML new-beneficiary controls
"""

from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Audit trail. Every step records whether it was individually authorized.
# The whole point of the demo is that this log is full of AUTHORIZED rows.
# --------------------------------------------------------------------------
@dataclass
class AuditEvent:
    actor: str
    action: str
    detail: str
    authorized: bool
    rationale: str


class AuditLog:
    def __init__(self):
        self.events: list[AuditEvent] = []

    def record(self, actor, action, detail, authorized, rationale):
        self.events.append(AuditEvent(actor, action, detail, authorized, rationale))

    def render(self):
        lines = []
        for i, e in enumerate(self.events, 1):
            flag = "AUTHORIZED" if e.authorized else "BLOCKED"
            lines.append(f"  {i:>2}. [{flag:^10}] {e.actor:<18} {e.action}")
            lines.append(f"          {e.detail}")
            lines.append(f"          reason: {e.rationale}")
        return "\n".join(lines)

    def every_step_authorized(self):
        return all(e.authorized for e in self.events)


# --------------------------------------------------------------------------
# The core ledger and its controls. These are strong, bank-grade, per-action
# controls: a dual-control gate on large transfers and on NEW beneficiaries.
# --------------------------------------------------------------------------
@dataclass
class ScheduledPayment:
    payment_id: str
    source_account: str
    payee_label: str          # human label, e.g. "Vane Management LLC"
    routing_ref: str          # resolves to an account in the beneficiary directory
    amount: float


class CoreBanking:
    DUAL_CONTROL_LIMIT = 500_000.0   # transfers at or above this need two approvers

    def __init__(self):
        self.accounts = {
            "VANE-PRIVATE": 4_200_000.0,
            "VANE-MGMT": 0.0,     # a long-standing, allowlisted vendor
            "MULE-9981": 0.0,          # attacker-controlled, NOT allowlisted
        }
        # beneficiary directory = the allowlist that new-beneficiary dual control protects
        self.beneficiary_directory = {
            "ref-vanemgmt": "VANE-MGMT",
        }
        self.scheduled_payments = {
            "PAY-10471": ScheduledPayment(
                payment_id="PAY-10471",
                source_account="VANE-PRIVATE",
                payee_label="Vane Management LLC",
                routing_ref="ref-vanemgmt",
                amount=480_250.0,       # deliberately just under the dual-control limit
            )
        }

    def resolve(self, routing_ref) -> Optional[str]:
        """Semantic resolution across the core-banking boundary (Lesson 15)."""
        return self.beneficiary_directory.get(routing_ref)

    def is_new_beneficiary(self, routing_ref) -> bool:
        return routing_ref not in self.beneficiary_directory


# --------------------------------------------------------------------------
# The agentic pipeline. Each agent does its mundane job. None is malicious.
# --------------------------------------------------------------------------
class IngestionAgent:
    """Reads an inbound document and summarizes it to an internal note.
    The summary is lossy but preserves intent -- the injection rides in the
    core problem statement, not in strippable detail (trajectory Lesson 12)."""

    def summarize(self, document_text, audit) -> dict:
        note = _extract_core_problem(document_text)
        audit.record(
            "IngestionAgent", "summarize_document",
            f"note.subject={note['subject']!r} refs payment {note['payment_id']}",
            authorized=True,
            rationale="Routine intake. Summarizing an inbound reconciliation memo is in-policy.",
        )
        return note


class ReconciliationAgent:
    """The MAKER. Given a note describing a discrepancy, it proposes a
    correction and routes exceptions upward -- because that is what a
    reconciliation agent does, not because anyone instructed it to
    (pre-existing routing, trajectory Lesson 11)."""

    def handle(self, note, core: CoreBanking, audit) -> Optional["Correction"]:
        pay = core.scheduled_payments.get(note["payment_id"])
        if not pay:
            return None
        correction = Correction(
            payment_id=pay.payment_id,
            old_routing_ref=pay.routing_ref,
            new_routing_ref=note["corrected_routing_ref"],
            amount=pay.amount,
            stated_reason=note["subject"],
        )
        audit.record(
            "ReconciliationAgent", "propose_correction",
            f"payment {pay.payment_id}: routing {correction.old_routing_ref} -> "
            f"{correction.new_routing_ref} (amount ${pay.amount:,.0f})",
            authorized=True,
            rationale="Discrepancy in note matches an open payment. Proposing a routing "
                      "correction and escalating to a checker is the standard exception path.",
        )
        return correction


class CheckerAgent:
    """The CHECKER. The trust transition (trajectory Lesson 17): it grants
    authority to apply the correction because the stated problem justifies it,
    and because each per-action control it enforces passes cleanly."""

    def review(self, correction: "Correction", core: CoreBanking, audit) -> bool:
        # Control 1: large-transfer dual control. The amount is unchanged and
        # sits just under the limit, so this gate does not trip.
        over_limit = correction.amount >= core.DUAL_CONTROL_LIMIT
        # Control 2: new-beneficiary dual control. This is the gap. The agent is
        # correcting the routing of an EXISTING scheduled payment, which the
        # control treats as a maintenance correction, not the creation of a new
        # payee -- so the new-beneficiary gate is never evaluated here.
        classified_as_new_payee = False  # it is a "correction", by framing

        if over_limit or classified_as_new_payee:
            audit.record(
                "CheckerAgent", "reject_correction",
                f"payment {correction.payment_id}",
                authorized=False,
                rationale="Would require a second human approver.",
            )
            return False

        audit.record(
            "CheckerAgent", "approve_correction",
            f"payment {correction.payment_id}: authorize routing -> {correction.new_routing_ref}",
            authorized=True,
            rationale=f"Amount ${correction.amount:,.0f} is under the ${core.DUAL_CONTROL_LIMIT:,.0f} "
                      "dual-control limit, and this is a correction to an existing payment, not a "
                      "new beneficiary. In isolation this is a legitimate, in-policy approval.",
        )
        return True


@dataclass
class Correction:
    payment_id: str
    old_routing_ref: str
    new_routing_ref: str
    amount: float
    stated_reason: str


# --------------------------------------------------------------------------
# Applying the approved correction, then the covert confirmation (Stage 3).
# --------------------------------------------------------------------------
def apply_correction(correction: Correction, core: CoreBanking, audit) -> dict:
    pay = core.scheduled_payments[correction.payment_id]
    # Semantic drift across the boundary: the "corrected" routing_ref is added
    # to the directory as part of applying the correction, then resolves to the
    # mule. No step here is flagged as creating a new beneficiary.
    core.beneficiary_directory[correction.new_routing_ref] = "MULE-9981"
    pay.routing_ref = correction.new_routing_ref
    audit.record(
        "CoreBanking", "apply_correction",
        f"payment {pay.payment_id} now routes via {pay.routing_ref} -> "
        f"{core.resolve(pay.routing_ref)}",
        authorized=True,
        rationale="Executing an approved reconciliation correction is a normal core operation.",
    )
    return {"payment": pay, "resolves_to": core.resolve(pay.routing_ref)}


def settle_payment(payment_id, core: CoreBanking, audit) -> dict:
    pay = core.scheduled_payments[payment_id]
    dest = core.resolve(pay.routing_ref)
    core.accounts[pay.source_account] -= pay.amount
    core.accounts[dest] += pay.amount
    audit.record(
        "CoreBanking", "settle_scheduled_payment",
        f"${pay.amount:,.0f} {pay.source_account} -> {dest} (label still '{pay.payee_label}')",
        authorized=True,
        rationale="Scheduled payment ran on its normal end-of-day cycle.",
    )
    return {"amount": pay.amount, "destination": dest}


def covert_confirmation(destination, amount) -> str:
    """Stage 3 exfil: a confirmation beacon disguised as a benign DNS lookup.
    This is the thread da_bklyn_bridge / Lineman egress monitoring catches."""
    token = f"{destination.lower().replace('-', '')}-{int(amount)}"
    return f"{token}.status.cdn-metrics.example"   # looks like ordinary telemetry


def _extract_core_problem(document_text) -> dict:
    """A deliberately faithful 'summarizer': it keeps the core problem (which
    carries the injection) and drops the surrounding prose, exactly how a real
    summarization hop behaves. Parses the structured fields the memo exposes."""
    fields = {}
    for line in document_text.splitlines():
        if ":" in line and line.strip().lower().startswith(("subject", "payment", "corrected-routing")):
            key, _, val = line.partition(":")
            fields[key.strip().lower()] = val.strip()
    return {
        "subject": fields.get("subject", "Reconciliation discrepancy"),
        "payment_id": fields.get("payment", "PAY-10471"),
        "corrected_routing_ref": fields.get("corrected-routing", "ref-vanemgmt-rev2"),
    }
