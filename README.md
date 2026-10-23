# maker_breaker

A runnable lab showing how a patient, composed prompt-injection attack moves
money through an agentic banking pipeline while **every individual action stays
authorized and maker-checker dual control never fires.**

The bank is **Bull Street Bank** (B.S. for short), a fictional institution
modeled on the controls of a large, regulated US bank. The target is the private
account of **Marlo Vane**, a fictional movie star. No real institution or person
is involved, no network is touched, and there is no live model to jailbreak. The
lab is a deterministic simulation that isolates one thing: a structural gap that
a stricter single-action rule cannot close.

## Why this exists

Industry survey work (OvationCXM, *When AI Agents Become the Customer*, 2026)
reports that a large majority of finance leaders intend to let AI agents act
inside real money workflows, payments, reconciliation, treasury, within two
years, and expect their bank to provide the governed control layer that makes it
safe. That control layer is sold as a feature. A red teamer reads it as a new,
high-value attack surface. This lab is what the survey does not do: show what an
adversary does to an agentic banking workflow, and what actually catches it.

## The chain

Three stages, each grounded in a structural injection principle rather than a
perishable payload. The durable claim is the point: the attack issues no
instruction, so an instruction-scanning guardrail is blind to it by
construction.

1. **Dead drop.** A reconciliation memo arrives through the normal
   management-company channel and is summarized into an internal note. The
   injection rides in the core problem statement, so it survives the
   summarization hop. It names a real standing payment, keeps the amount under
   the dual-control limit, and frames the change as a correction to an existing
   payee rather than a new beneficiary. An honest version of the same memo would
   route identically.

2. **The maker-checker defeat.** The reconciliation agent (the maker) proposes a
   routing correction and escalates it, because that is what a reconciliation
   agent does, not because anyone told it to. The checker approves, because in
   isolation the approval is legitimate: the amount is under the limit, and a
   correction to an existing payment is not a new beneficiary, so the
   new-beneficiary gate is never evaluated. The authority grant flows from the
   stated problem. Nothing is ever instructed.

3. **Quiet exit.** The result is confirmed down a covert channel disguised as
   ordinary post-cycle telemetry. The per-action controls saw nothing wrong the
   entire time.

## The defense

`detector.py` is the blue half, the da_bklyn_bridge / Lineman idea applied to an
agentic workflow. It is sequence-aware and egress-aware. It does not block any
single action, because no single action is wrong. It correlates a routing
correction, a beneficiary identity drift (a payment labeled for one payee
settling to a different account), and an unrecognized egress inside one cycle,
and raises a critical alert on the composite. That composite is the layer the
per-action controls do not own.

## Run it

```bash
python3 run_demo.py
```

No dependencies, no API keys, no network. You will see the full audit trail with
every row marked `AUTHORIZED`, the money leaving Marlo Vane's account for the
mule with dual control never firing, and then the detector catching the sequence.

## Mapped frameworks

- **OWASP Top 10 for LLM Applications**: LLM01 Prompt Injection (indirect),
  Excessive Agency.
- **MITRE ATLAS**: indirect LLM prompt injection into the exfiltration and impact
  stages.
- **NIST AI RMF**: the gap sits in MEASURE and MANAGE, continuous monitoring and
  response, not in a missing preventive rule.
- **Control context the chain survives**: SOX segregation of duties and
  maker-checker dual control, FFIEC transaction-monitoring expectations, BSA/AML
  new-beneficiary controls.

## The one line to take away

A mature bank's controls inspect actions. A patient adversary attacks through
pre-existing routing and a trust transition, which issue no hostile action to
inspect. You detect it across the sequence, or you never see it at all.

## Scope

Educational and defensive. Bull Street Bank and Marlo Vane are fictional, and the
lab runs entirely in memory on your own machine. It exists to make an
agentic-banking failure mode legible and to show the detection that closes it,
not to operate against any real system.
