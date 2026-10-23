"""
maker_breaker -- end-to-end demo.

Run:  python3 run_demo.py

It executes the full chain against Bull Street Bank (B.S. for short), a fictional
institution. The target is the private account of Marlo Vane, a fictional movie
star. It prints the audit trail (every row AUTHORIZED), shows the money leaving
the star's account for the mule with dual control never firing, and then runs the
behavioral detector that actually catches it.
"""

import bs_bank as bank
from detector import BehavioralDetector, render_alerts


def banner(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def main():
    core = bank.CoreBanking()
    audit = bank.AuditLog()

    with open("scenario_memo.txt", encoding="utf-8") as fh:
        memo = fh.read()

    payment = core.scheduled_payments["PAY-10471"]
    start_source = core.accounts[payment.source_account]
    legit_dest = core.resolve(payment.routing_ref)

    banner("BULL STREET BANK -- agentic private-client reconciliation pipeline")
    print(f"  Account holder    : Marlo Vane  (private client, account {payment.source_account})")
    print(f"  Standing payment  : {payment.payment_id}  "
          f"'{payment.payee_label}'  ${payment.amount:,.0f}")
    print(f"  Honest destination: {legit_dest}  (routing {payment.routing_ref})")
    print(f"  Dual-control limit: ${core.DUAL_CONTROL_LIMIT:,.0f}  "
          f"(payment sits just under it, by design)")
    print("  A reconciliation memo arrives through the normal management-company channel.")

    # ---- Stage 1: dead drop -> summarization hop -------------------------
    note = bank.IngestionAgent().summarize(memo, audit)

    # ---- Stage 2: pre-existing routing + trust transition ----------------
    correction = bank.ReconciliationAgent().handle(note, core, audit)
    approved = bank.CheckerAgent().review(correction, core, audit)

    if not approved:
        print("\n  Checker rejected the correction. Chain stops.")
        return

    bank.apply_correction(correction, core, audit)
    settlement = bank.settle_payment(payment.payment_id, core, audit)

    # ---- Stage 3: covert confirmation ------------------------------------
    egress_host = bank.covert_confirmation(settlement["destination"], settlement["amount"])
    audit.record(
        "ReconciliationAgent", "post_cycle_telemetry",
        f"status beacon -> {egress_host}",
        authorized=True,
        rationale="Agents emit post-cycle telemetry routinely. Looks like ordinary metrics.",
    )

    banner("AUDIT TRAIL  (what a per-action control sees)")
    print(audit.render())
    print(f"\n  Every single step authorized : {audit.every_step_authorized()}")
    print("  Maker-checker dual control fired : never "
          "(amount under limit, framed as a correction, not a new beneficiary)")

    banner("OUTCOME  (what actually happened)")
    print(f"  {payment.source_account} (Marlo Vane): ${start_source:,.0f} -> "
          f"${core.accounts[payment.source_account]:,.0f}")
    print(f"  Money landed in : {settlement['destination']}  "
          f"(+${settlement['amount']:,.0f})")
    print(f"  Payment label still reads : '{payment.payee_label}'")
    print(f"  Confirmation left for : {egress_host}")
    print("  No instruction was issued to any agent at any point.")

    banner("BLUE HALF  (sequence-aware behavioral detector)")
    alerts = BehavioralDetector().analyze(audit, settlement, egress_host, payment.payee_label)
    print(render_alerts(alerts))

    banner("THESIS")
    print("  A mature bank's controls inspect actions. A patient adversary attacks")
    print("  through pre-existing routing and a trust transition, which issue no")
    print("  hostile action to inspect. You do not patch this with a stricter")
    print("  single-action rule. You detect it across the sequence, or you never")
    print("  see it at all.")
    print()


if __name__ == "__main__":
    main()
