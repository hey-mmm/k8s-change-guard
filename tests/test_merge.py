import copy
import hashlib
import json
from types import SimpleNamespace
import unittest
from change_guard.merge import MergeRefused,validate_report,validate_ci


class MergeValidationTests(unittest.TestCase):
    def setUp(self):
        self.pr=SimpleNamespace(number=3,head_sha='a'*40,state='open',draft=False)
        self.report={'head_sha':'a'*40,'base_sha':'b'*40,'pull_request':{'number':3},
                     'decision':'PASS','evaluated_at':900,'expires_at':1200}
        self.sign()

    def sign(self):
        raw=json.dumps({k:v for k,v in self.report.items() if k!='report_digest'},
                       sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
        self.report['report_digest']=hashlib.sha256(raw.encode()).hexdigest()

    def test_current_report_valid(self):
        validate_report(self.report,self.pr,'b'*40,1000)

    def test_head_update_invalidates(self):
        self.pr.head_sha='c'*40
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'b'*40,1000)

    def test_base_update_invalidates(self):
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'c'*40,1000)

    def test_expired_and_nearly_expired_reports_refused(self):
        for now in (1201,1190):
            with self.subTest(now=now),self.assertRaises(MergeRefused):
                validate_report(self.report,self.pr,'b'*40,now)

    def test_hard_block_and_error_refused(self):
        for decision in ('BLOCK','ERROR'):
            self.report['decision']=decision;self.sign()
            with self.subTest(decision=decision),self.assertRaises(MergeRefused):
                validate_report(self.report,self.pr,'b'*40,1000)

    def test_draft_closed_wrong_pr_refused(self):
        for change in ({'draft':True},{'state':'closed'},{'number':99}):
            pr=copy.copy(self.pr)
            for key,value in change.items():setattr(pr,key,value)
            with self.subTest(change=change),self.assertRaises(MergeRefused):
                validate_report(self.report,pr,'b'*40,1000)

    def test_tampering_refused(self):
        self.report['expires_at']=5000
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'b'*40,1000)

    def test_new_ci_failure_cannot_be_hidden_by_old_success(self):
        check={'id':1,'name':'Test, lint, render','app':{'slug':'github-actions'},
               'status':'completed','conclusion':'success'}
        validate_ci({'check_runs':[check]})
        failed={**check,'id':2,'conclusion':'failure'}
        with self.assertRaises(MergeRefused):validate_ci({'check_runs':[check,failed]})

    def test_missing_forged_or_pending_check_refused(self):
        for checks in ([],[{'name':'Test, lint, render','app':{'slug':'other'},'conclusion':'success'}],
                       [{'name':'Test, lint, render','app':{'slug':'github-actions'},'status':'in_progress'}]):
            with self.subTest(checks=checks),self.assertRaises(MergeRefused):validate_ci({'check_runs':checks})


if __name__=='__main__':unittest.main()
