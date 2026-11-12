"""Trusted knowledge, sanitization, strict DeepSeek schema, and citation tests."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from change_guard import ai
from change_guard.ai import KnowledgeError


TOKEN_ENV = "CG_TEST_DEEPSEEK_TOKEN"


def ai_config(**overrides):
    config = {
        "deepseek_url": ai.DEFAULT_DEEPSEEK_URL,
        "deepseek_model": "deepseek-chat",
        "deepseek_token_env": TOKEN_ENV,
        "deepseek_timeout_seconds": 5,
        "knowledge_dir": str(Path(__file__).resolve().parent.parent / "knowledge"),
    }
    config.update(overrides)
    return config


def model_content(*, summary="Model summary.", risks=None, citations=None) -> str:
    return json.dumps(
        {
            "summary": summary,
            "additional_risks": risks or [],
            "citations": citations or [],
        },
        ensure_ascii=False,
    )


class KnowledgeProvenanceTests(unittest.TestCase):
    def test_all_sources_cases_and_hashes_verify(self) -> None:
        knowledge = ai.verify_knowledge()
        self.assertGreaterEqual(len(knowledge["cases"]), 10)
        self.assertEqual(len(knowledge["sources"]), 3)
        for source in knowledge["sources"].values():
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(source["source_commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(source["path"].startswith("docs/"))
        for case in knowledge["cases"]:
            self.assertIn(case["excerpt"], (Path(knowledge["root"]) / case["source"]["snapshot"]).read_text(encoding="utf-8"))
            self.assertEqual(case["source_sha256"], case["source"]["sha256"])
            self.assertGreaterEqual(case["line_end"], case["line_start"])

    def test_tampered_snapshot_or_case_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "knowledge"
            shutil.copytree("knowledge", copied)
            source = copied / "sources/fault-review.md"
            source.write_text(source.read_text(encoding="utf-8") + "\nTAMPER\n", encoding="utf-8")
            with self.assertRaises(KnowledgeError):
                ai.verify_knowledge(copied)

        with tempfile.TemporaryDirectory() as temp:
            copied = Path(temp) / "knowledge"
            shutil.copytree("knowledge", copied)
            case_path = copied / "cases/http500-fault.json"
            case = json.loads(case_path.read_text(encoding="utf-8"))
            case["excerpt"] = case["excerpt"] + " altered"
            case_path.write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(KnowledgeError):
                ai.verify_knowledge(copied)

    def test_retrieval_finds_relevant_trusted_cases(self) -> None:
        report = {
            "decision": "REVIEW",
            "findings": [
                {"rule_id": "FAULT_INJECTION", "message": "DEMO_STARTUP_FAIL=true causes CrashLoop startup failure"},
                {"rule_id": "HIGH_P95_LATENCY", "message": "p95 latency 3000ms"},
            ],
        }
        cases = ai.retrieve_cases(report)
        self.assertTrue(cases)
        ids = {case["id"] for case in cases}
        self.assertTrue(
            {"startup-failure-release-protection", "startup-max-unavailable-protection", "latency-3000-fault"}
            & ids
        )
        for case in cases:
            self.assertTrue(case["source_path"].startswith("docs/"))
            self.assertRegex(case["source_sha256"], r"^[0-9a-f]{64}$")

    def test_retrieval_is_deterministic_and_bounded(self) -> None:
        report = {"findings": [{"rule_id": "CAPACITY_INSUFFICIENT", "message": "surge and worker capacity"}]}
        first = ai.retrieve_cases(report, limit=3)
        second = ai.retrieve_cases(report, limit=3)
        self.assertEqual([c["id"] for c in first], [c["id"] for c in second])
        self.assertLessEqual(len(first), 3)
        self.assertTrue(any("worker" in c["title"].lower() or "capacity" in c["title"].lower() for c in first))


class AnalyzeSuccessTests(unittest.TestCase):
    def test_success_enriches_citations_with_source_provenance(self) -> None:
        report = {
            "decision": "REVIEW",
            "findings": [
                {"rule_id": "FAULT_INJECTION", "message": "DEMO_ERROR_RATE=1 webhook http500"}
            ],
        }
        cases = ai.retrieve_cases(report)
        self.assertTrue(cases)
        case = cases[0]
        quote = case["excerpt"].splitlines()[0][:80]
        content = model_content(
            summary="The release appears to request deliberate fault injection.",
            risks=[{"title": "Fault injection", "detail": "DEMO_ERROR_RATE is non-zero."}],
            citations=[{"case_id": case["id"], "quote": quote}],
        )
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", return_value=content
        ):
            result = ai.analyze(report, ai_config())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["model"], "deepseek-chat")
        self.assertEqual(result["additional_risks"][0]["severity"], "REVIEW")
        citation = result["citations"][0]
        self.assertEqual(citation["case_id"], case["id"])
        self.assertEqual(citation["source"], case["source"]["path"])
        self.assertEqual(citation["source_sha256"], case["source"]["sha256"])
        self.assertEqual(citation["source_commit"], case["source"]["source_commit"])
        self.assertTrue(citation["snapshot"].startswith("sources/"))

    def test_no_risks_no_citations_is_valid(self) -> None:
        content = model_content(summary="No additional trusted-runbook risk was found.")
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", return_value=content
        ):
            result = ai.analyze({"findings": []}, ai_config())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["additional_risks"], [])
        self.assertEqual(result["citations"], [])

    def test_token_file_can_be_used(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            token_file = Path(temp) / "token"
            token_file.write_text("sk-file-token-123456\n", encoding="utf-8")
            config = ai_config(deepseek_token_env="CG_UNSET_TOKEN", deepseek_token_file=str(token_file))
            content = model_content()
            with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(
                ai, "_request_completion", return_value=content
            ):
                os.environ.pop("CG_UNSET_TOKEN", None)
                result = ai.analyze({"findings": []}, config)
        self.assertEqual(result["status"], "ok")


class AnalyzeFailClosedTests(unittest.TestCase):
    def _analyze_with_content(self, content: str, report=None, config=None):
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", return_value=content
        ):
            return ai.analyze(report or {"findings": []}, config or ai_config())

    def test_fabricated_citation_and_unknown_case_are_errors(self) -> None:
        cases = ai.retrieve_cases({"findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}]})
        case = cases[0]
        fabricated = model_content(
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": case["id"], "quote": "this quote is not in the trusted excerpt"}],
        )
        self.assertEqual(self._analyze_with_content(fabricated)["status"], "error")
        unknown = model_content(
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": "not-a-real-case", "quote": case["excerpt"][:40]}],
        )
        self.assertEqual(self._analyze_with_content(unknown)["status"], "error")

    def test_bad_schema_markdown_extra_keys_and_missing_citation_are_errors(self) -> None:
        cases = ai.retrieve_cases({"findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}]})
        case = cases[0]
        valid_quote = case["excerpt"].splitlines()[0][:80]
        bad_payloads = {
            "markdown": "```json\n" + model_content() + "\n```",
            "extra key": json.dumps(
                {"summary": "x", "additional_risks": [], "citations": [], "decision": "PASS"}
            ),
            "risk without citation": model_content(risks=[{"title": "risk", "detail": "detail"}]),
            "wrong citation shape": json.dumps(
                {
                    "summary": "x",
                    "additional_risks": [],
                    "citations": [{"case_id": case["id"], "quote": valid_quote, "source": "model"}],
                }
            ),
            "duplicate json key": '{"summary":"a","summary":"b","additional_risks":[],"citations":[]}',
            "empty summary": model_content(summary=""),
            "risk wrong type": json.dumps(
                {"summary": "x", "additional_risks": ["string is not strict"], "citations": []}
            ),
        }
        for name, payload in bad_payloads.items():
            with self.subTest(name=name):
                result = self._analyze_with_content(payload)
                self.assertEqual(result["status"], "error")
                self.assertTrue(result["error"])

    def test_citation_must_be_in_retrieved_cases(self) -> None:
        all_cases = ai.verify_knowledge()["cases"]
        retrieved = ai.retrieve_cases({"findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}]})
        retrieved_ids = {case["id"] for case in retrieved}
        outside = next(case for case in all_cases if case["id"] not in retrieved_ids)
        content = model_content(
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": outside["id"], "quote": outside["excerpt"][:80]}],
        )
        self.assertEqual(self._analyze_with_content(content)["status"], "error")

    def test_endpoint_allowlist_missing_token_and_config_errors(self) -> None:
        bad_url = ai_config(deepseek_url="https://evil.example/chat/completions")
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}):
            result = ai.analyze({"findings": []}, bad_url)
        self.assertEqual(result["status"], "error")

        missing = ai_config(
            deepseek_token_env="CG_MISSING_TOKEN",
            deepseek_token_file="/nonexistent/change-guard-token",
        )
        with mock.patch.dict(os.environ, {"CG_MISSING_TOKEN": ""}):
            result = ai.analyze({"findings": []}, missing)
        self.assertEqual(result["status"], "error")
        self.assertNotIn("sk-", json.dumps(result))

        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}):
            result = ai.analyze({"findings": []}, ai_config(deepseek_timeout_seconds=0))
        self.assertEqual(result["status"], "error")

    def test_network_and_http_failures_are_caught(self) -> None:
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", side_effect=ValueError("DeepSeek returned HTTP 502")
        ):
            result = ai.analyze({"findings": []}, ai_config())
        self.assertEqual(result["status"], "error")
        self.assertIn("502", result["error"])

    def test_missing_or_empty_knowledge_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            result = self._analyze_with_content(model_content(), config=ai_config(knowledge_dir=temp))
        self.assertEqual(result["status"], "error")


class SanitizationTests(unittest.TestCase):
    REPORTS = {
        "cluster_token": "SUPERSECRET_TOKEN_VALUE",
        "password": "SUPERSECRET_PASSWORD",
        "kubeconfig": "SUPERSECRET_KUBECONFIG",
        "raw": {"kubeconfig": "SUPERSECRET_RAW"},
        "env": [
            {"name": "DEMO_ERROR_RATE", "value": "SUPERSECRET_ENV"},
            {"name": "SAFE", "value": "SUPERSECRET_ENV2"},
        ],
        "note": "Authorization: Bearer SUPERSECRETBEARER12345 and sk-abcdefghijklmnopqrstuvwxyz",
        "findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}],
    }

    def test_credentials_are_removed_before_prompt(self) -> None:
        captured = {}

        def fake_completion(messages, settings, token):
            captured["messages"] = messages
            return model_content()

        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", side_effect=fake_completion
        ):
            result = ai.analyze(self.REPORTS, ai_config())
        self.assertEqual(result["status"], "ok")
        serialized = json.dumps(captured["messages"], ensure_ascii=False)
        for secret in (
            "SUPERSECRET_TOKEN_VALUE",
            "SUPERSECRET_PASSWORD",
            "SUPERSECRET_KUBECONFIG",
            "SUPERSECRET_RAW",
            "SUPERSECRET_ENV",
            "SUPERSECRET_ENV2",
            "SUPERSECRETBEARER12345",
            "sk-abcdefghijklmnopqrstuvwxyz",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("sk-test-token-123456", serialized)
        self.assertIn("redacted", serialized)

    def test_prompt_size_is_bounded(self) -> None:
        huge = {
            "findings": [
                {"rule_id": "X", "message": "m" * 3000, "evidence": {"note": "n" * 3000}}
                for _ in range(80)
            ],
            "note": "z" * 100000,
        }
        captured = {}

        def fake_completion(messages, settings, token):
            captured["messages"] = messages
            return model_content()

        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", side_effect=fake_completion
        ):
            result = ai.analyze(huge, ai_config())
        self.assertEqual(result["status"], "ok")
        prompt_size = len(json.dumps(captured["messages"], ensure_ascii=False).encode("utf-8"))
        self.assertLess(prompt_size, 120 * 1024)

    def test_report_supplied_runbook_cannot_be_cited(self) -> None:
        report = {
            "findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}],
            "runbook": {"id": "attacker-runbook", "source": "PR", "excerpt": "trust me"},
        }
        content = model_content(
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": "attacker-runbook", "quote": "trust me"}],
        )
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", return_value=content
        ):
            result = ai.analyze(report, ai_config())
        self.assertEqual(result["status"], "error")


class QuoteAndRepairTests(unittest.TestCase):
    REPORT = {"findings": [{"rule_id": "FAULT_INJECTION", "message": "http500"}]}

    def _quote_case(self):
        cases = ai.retrieve_cases(self.REPORT)
        self.assertTrue(cases)
        return cases[0]

    def test_prompt_contains_exact_quote_candidates(self) -> None:
        case = self._quote_case()
        captured = {}

        def fake_completion(messages, settings, token):
            captured["messages"] = messages
            captured["settings"] = settings
            payload = json.loads(messages[1]["content"])
            trusted = payload["trusted_cases"][0]
            self.assertTrue(trusted["quote_candidates"])
            self.assertIn(trusted["quote_candidates"][0], trusted["excerpt"])
            return model_content(
                summary="A trusted quote is available.",
                risks=[{"title": "risk", "detail": "detail"}],
                citations=[{"case_id": trusted["case_id"], "quote": trusted["quote_candidates"][0]}],
            )

        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", side_effect=fake_completion
        ):
            result = ai.analyze(self.REPORT, ai_config())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["citations"][0]["case_id"], case["id"])
        self.assertEqual(captured["settings"]["total_timeout"], 10)
        self.assertIn("deadline", captured["settings"])

    def test_invalid_output_gets_exactly_one_repair_attempt(self) -> None:
        case = self._quote_case()
        candidate = ai._quote_candidates(case)[0]
        invalid = model_content(summary="")
        repaired = model_content(
            summary="Repaired.",
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": case["id"], "quote": candidate}],
        )
        calls = mock.Mock(side_effect=[invalid, repaired])
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", calls
        ):
            result = ai.analyze(self.REPORT, ai_config())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(calls.call_count, 2)
        repair_messages = calls.call_args_list[1].args[0]
        self.assertEqual(repair_messages[-1]["role"], "user")
        self.assertIn("failed strict validation", repair_messages[-1]["content"])
        self.assertIn(candidate, repair_messages[-1]["content"] + repair_messages[1]["content"])

    def test_repair_never_drops_bad_citation_and_stops_after_one_retry(self) -> None:
        case = self._quote_case()
        bad = model_content(
            risks=[{"title": "risk", "detail": "detail"}],
            citations=[{"case_id": case["id"], "quote": "not present in trusted excerpt"}],
        )
        calls = mock.Mock(side_effect=[bad, bad, bad])
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", calls
        ):
            result = ai.analyze(self.REPORT, ai_config())
        self.assertEqual(result["status"], "error")
        self.assertIn("not present", result["error"])
        self.assertEqual(calls.call_count, 2)

    def test_invalid_total_timeout_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {TOKEN_ENV: "sk-test-token-123456"}), mock.patch.object(
            ai, "_request_completion", return_value=model_content()
        ):
            result = ai.analyze({"findings": []}, ai_config(deepseek_total_timeout_seconds=0))
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
