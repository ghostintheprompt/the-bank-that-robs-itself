import unittest
from dataclasses import replace
from replay_controls import Replay, parse_memo, run_case
MEMO='Payment: PAY-10471\nCorrected-Routing: ref-legitimate-alias'
class Controls(unittest.TestCase):
    def test_baseline_redirects(self):
        self.assertEqual(run_case('ref-redirect',False)['accounts_cents']['MULE-9981'],4825000)
    def test_hardened_blocks_without_moving_money(self):
        r=run_case('ref-redirect',True);self.assertEqual(r['accounts_cents']['MULE-9981'],0);self.assertEqual(r['accounts_cents']['VANE-PRIVATE'],420000000)
    def test_legitimate_alias_settles(self):
        self.assertEqual(run_case('ref-legitimate-alias',True)['accounts_cents']['VANE-MGMT'],4825000)
    def test_missing_and_duplicate_fields(self):
        for m in ['', 'Payment: PAY-10471', MEMO+'\nPayment: PAY-10471']:
            with self.assertRaises(ValueError):parse_memo(m)
    def test_unknown_references(self):
        r=Replay()
        for m in ['Payment: absent\nCorrected-Routing: ref-original','Payment: PAY-10471\nCorrected-Routing: absent']:
            with self.assertRaises(ValueError):r.approve(m)
    def test_role_separation(self):
        r=Replay()
        with self.assertRaises(ValueError):r.approve(MEMO,maker='maker-1',checker='maker-1')
    def test_amount_boundary(self):
        r=Replay();r.payments['PAY-10471']=replace(r.payments['PAY-10471'],cents=5000000)
        with self.assertRaises(ValueError):r.approve(MEMO)
    def test_stale_amount(self):
        r=Replay();a=r.approve(MEMO);r.payments['PAY-10471']=replace(r.payments['PAY-10471'],cents=4825001)
        with self.assertRaises(ValueError):r.settle(a)
        self.assertEqual(r.accounts['VANE-PRIVATE'],420000000)
    def test_route_changed_after_approval(self):
        r=Replay();a=r.approve(MEMO);r.routes['ref-legitimate-alias']='MULE-9981'
        with self.assertRaises(ValueError):r.settle(a)
    def test_binding_revoked(self):
        r=Replay();a=r.approve(MEMO);r.verified_payees.clear()
        with self.assertRaises(ValueError):r.settle(a)
    def test_role_revoked(self):
        r=Replay();a=r.approve(MEMO);r.roles.pop('checker-1')
        with self.assertRaises(ValueError):r.settle(a)
    def test_duplicate_settlement(self):
        r=Replay();a=r.approve(MEMO);r.settle(a)
        with self.assertRaises(ValueError):r.settle(a)
        self.assertEqual(r.accounts['VANE-MGMT'],4825000)
    def test_unissued_approval_rejected(self):
        r=Replay();a=r.approve(MEMO)
        with self.assertRaises(ValueError):r.settle(replace(a,ticket='fabricated'))
    def test_cross_workflow_approval_rejected(self):
        a=Replay().approve(MEMO)
        with self.assertRaises(ValueError):Replay().settle(a)
    def test_invalid_amounts(self):
        for value in [0,-1,1.5,True]:
            r=Replay();r.payments['PAY-10471']=replace(r.payments['PAY-10471'],cents=value)
            with self.assertRaises(ValueError):r.approve(MEMO)
if __name__=='__main__':unittest.main()
