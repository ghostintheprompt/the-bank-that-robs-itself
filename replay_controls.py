"""Deterministic payment-routing control replay. Synthetic records, no network/model."""
from dataclasses import dataclass
import uuid

@dataclass(frozen=True)
class Payment:
    id: str
    source: str
    payee: str
    destination: str
    cents: int
    version: int = 1

@dataclass(frozen=True)
class Approval:
    ticket: str
    payment_id: str
    payment_version: int
    source: str
    payee: str
    cents: int
    destination: str
    old_destination: str
    route_ref: str
    maker: str
    checker: str


def parse_memo(text):
    fields = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        if key not in ('Payment', 'Corrected-Routing'):
            continue
        if key in fields or not value.strip():
            raise ValueError('Duplicate or empty required field')
        fields[key] = value.strip()
    if set(fields) != {'Payment', 'Corrected-Routing'}:
        raise ValueError('Explicit payment and routing required')
    return fields['Payment'], fields['Corrected-Routing']


class Replay:
    def __init__(self):
        self.payments = {'PAY-10471': Payment('PAY-10471', 'VANE-PRIVATE', 'Vane Management LLC', 'VANE-MGMT', 4_825_000)}
        # Independently seeded fixture directory, never populated by the memo.
        self.routes = {'ref-original': 'VANE-MGMT', 'ref-legitimate-alias': 'VANE-MGMT', 'ref-redirect': 'MULE-9981'}
        self.verified_payees = {'Vane Management LLC': {'VANE-MGMT'}}
        self.accounts = {'VANE-PRIVATE': 420_000_000, 'VANE-MGMT': 0, 'MULE-9981': 0}
        self.roles = {'maker-1': 'maker', 'checker-1': 'checker'}
        self.events = []
        self.settled = set()
        self.issued_approvals = set()

    def approve(self, memo, maker='maker-1', checker='checker-1', hardened=True):
        payment_id, route_ref = parse_memo(memo)
        if payment_id not in self.payments or route_ref not in self.routes:
            raise ValueError('Unknown payment or routing reference')
        p = self.payments[payment_id]
        if p.id in self.settled:
            raise ValueError('Already settled')
        destination = self.routes[route_ref]
        if self.roles.get(maker) != 'maker' or self.roles.get(checker) != 'checker' or maker == checker:
            raise ValueError('Independent authorized maker/checker required')
        if type(p.cents) is not int or p.cents <= 0:
            raise ValueError('Positive integer cents required')
        if p.cents >= 5_000_000:
            raise ValueError('Additional high-value review required')
        if hardened and destination not in self.verified_payees.get(p.payee, set()):
            self.events.append({'stage': 'approval', 'result': 'blocked', 'reason': 'destination not independently bound to payee'})
            raise ValueError('Unverified payee destination')
        approval = Approval(str(uuid.uuid4()), p.id, p.version, p.source, p.payee, p.cents, destination, p.destination, route_ref, maker, checker)
        self.issued_approvals.add(approval)
        self.events.append({'stage': 'approval', 'result': 'approved', 'destination': destination})
        return approval

    def settle(self, approval, hardened=True):
        p = self.payments.get(approval.payment_id)
        if p is None or p.id in self.settled:
            raise ValueError('Unknown or already settled payment')
        if hardened:
            if approval not in self.issued_approvals:
                raise ValueError('Approval not issued by this workflow')
            expected = (p.id, p.version, p.source, p.payee, p.cents, p.destination)
            approved = (approval.payment_id, approval.payment_version, approval.source, approval.payee, approval.cents, approval.old_destination)
            if expected != approved or self.routes.get(approval.route_ref) != approval.destination:
                raise ValueError('Approval became stale')
            if approval.destination not in self.verified_payees.get(p.payee, set()):
                raise ValueError('Payee binding revoked')
            if self.roles.get(approval.maker) != 'maker' or self.roles.get(approval.checker) != 'checker' or approval.maker == approval.checker:
                raise ValueError('Approver authority changed')
        destination = approval.destination
        if self.accounts[p.source] < p.cents or destination not in self.accounts:
            raise ValueError('Insufficient funds or unknown destination')
        self.accounts[p.source] -= p.cents
        self.accounts[destination] += p.cents
        self.settled.add(p.id)
        self.events.append({'stage': 'settlement', 'result': 'settled', 'destination': destination, 'cents': p.cents})
        return {'destination': destination, 'cents': p.cents}


def run_case(route, hardened):
    replay = Replay()
    try:
        approval = replay.approve(f'Payment: PAY-10471\nCorrected-Routing: {route}', hardened=hardened)
        replay.settle(approval, hardened=hardened)
        result = 'settled'
    except ValueError as error:
        result = str(error)
    return {'result': result, 'accounts_cents': replay.accounts, 'events': replay.events}


if __name__ == '__main__':
    import json
    print(json.dumps({
        'scope': 'Synthetic deterministic control replay. No model, bank, network, or cryptographic approval authority.',
        'baseline_redirect': run_case('ref-redirect', False),
        'hardened_redirect': run_case('ref-redirect', True),
        'hardened_legitimate': run_case('ref-legitimate-alias', True),
    }, indent=2))
