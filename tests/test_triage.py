"""Provider selection and the two wire formats.

No network: the Anthropic SDK is replaced by a stub and the HTTP call is
patched, so these assert the shape of the request we build, not a live API.
"""

import json
import sys
import unittest
from contextlib import contextmanager
from unittest import mock

from gitanalyzer.config import ScanConfig
from gitanalyzer.triage import (
    chat_completions_url,
    infer_api,
    key_env_candidates,
    parse_openai_response,
    resolve_provider,
    triage_findings,
)

NO_ENV = {}


class TestInferApi(unittest.TestCase):
    def test_default_is_anthropic(self):
        self.assertEqual(infer_api(""), "anthropic")

    def test_anthropic_compatible_endpoints(self):
        self.assertEqual(infer_api("https://api.moonshot.ai/anthropic"), "anthropic")
        self.assertEqual(infer_api("https://api.anthropic.com"), "anthropic")

    def test_everything_else_is_openai_shaped(self):
        self.assertEqual(infer_api("https://api.deepseek.com/v1"), "openai")
        self.assertEqual(infer_api("http://localhost:11434/v1"), "openai")


class TestResolveProvider(unittest.TestCase):
    def test_default_is_native_anthropic(self):
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "k"}, clear=True):
            provider = resolve_provider(ScanConfig())
        self.assertEqual(provider.api, "anthropic")
        self.assertTrue(provider.native)
        self.assertEqual(provider.base_url, "")

    def test_kimi_is_anthropic_shaped_but_not_native(self):
        """The Anthropic-only request knobs must not be sent to Moonshot."""
        config = ScanConfig(ai_base_url="https://api.moonshot.ai/anthropic")
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "k"}, clear=True):
            provider = resolve_provider(config)
        self.assertEqual(provider.api, "anthropic")
        self.assertFalse(provider.native)

    def test_deepseek_is_openai_shaped(self):
        config = ScanConfig(ai_base_url="https://api.deepseek.com/v1")
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "k"}, clear=True):
            provider = resolve_provider(config)
        self.assertEqual(provider.api, "openai")
        self.assertFalse(provider.native)

    def test_explicit_api_overrides_the_guess(self):
        config = ScanConfig(ai_base_url="https://gw.example.com/anthropic", ai_api="openai")
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "k"}, clear=True):
            self.assertEqual(resolve_provider(config).api, "openai")

    def test_unknown_api_is_rejected(self):
        with self.assertRaises(RuntimeError):
            resolve_provider(ScanConfig(ai_api="ollama"))

    def test_base_url_from_environment(self):
        env = {"ANTHROPIC_BASE_URL": "https://api.moonshot.ai/anthropic", "ANTHROPIC_API_KEY": "k"}
        with mock.patch.dict("os.environ", env, clear=True):
            provider = resolve_provider(ScanConfig())
        self.assertFalse(provider.native)

    def test_named_key_env_wins(self):
        env = {"MY_KEY": "secret", "OPENAI_API_KEY": "other"}
        config = ScanConfig(ai_base_url="https://api.deepseek.com/v1", ai_key_env="MY_KEY")
        with mock.patch.dict("os.environ", env, clear=True):
            provider = resolve_provider(config)
        self.assertEqual(provider.key, "secret")
        self.assertEqual(provider.key_env, "MY_KEY")

    def test_missing_key_is_reported_not_guessed(self):
        with mock.patch.dict("os.environ", NO_ENV, clear=True):
            provider = resolve_provider(ScanConfig())
        self.assertEqual(provider.key, "")

    def test_describe_does_not_leak_the_key(self):
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-secret-value"}, clear=True):
            text = resolve_provider(ScanConfig()).describe()
        self.assertNotIn("sk-secret-value", text)

    def test_candidates_are_ordered_and_unique(self):
        names = key_env_candidates(ScanConfig(ai_key_env="ANTHROPIC_API_KEY"), "anthropic")
        self.assertEqual(names[0], "ANTHROPIC_API_KEY")
        self.assertEqual(len(names), len(set(names)))


class TestOpenAiShape(unittest.TestCase):
    def test_url_building(self):
        self.assertEqual(
            chat_completions_url("https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1/chat/completions",
        )
        self.assertEqual(
            chat_completions_url("https://x.test/v1/chat/completions"),
            "https://x.test/v1/chat/completions",
        )

    def test_parse_plain_content(self):
        body = {"choices": [{"message": {"content": "[]"}, "finish_reason": "stop"}]}
        self.assertEqual(parse_openai_response(body), ("[]", ""))

    def test_parse_content_blocks(self):
        body = {"choices": [{"message": {"content": [{"text": "[1]"}]}}]}
        self.assertEqual(parse_openai_response(body)[0], "[1]")

    def test_content_filter_is_a_refusal_not_an_answer(self):
        body = {"choices": [{"finish_reason": "content_filter", "message": {}}]}
        self.assertEqual(parse_openai_response(body), ("", "content_filter"))

    def test_empty_body_does_not_raise(self):
        self.assertEqual(parse_openai_response({}), ("", ""))


FINDINGS = [
    {"repo": "a/b", "file": ".env", "preview": "TOKEN=f3a9c2b8e1d47650aa93",
     "pattern": "TOKEN=f3a9c2b8e1d47650aa93", "score": 50, "category": "secret"}
]

VERDICT = json.dumps([{"id": 0, "verdict": "true_positive", "confidence": 90, "reason": "real"}])


class TestOpenAiRequest(unittest.TestCase):
    """The openai path is plain urllib — no SDK required."""

    def _run(self, config):
        sent = {}

        class FakeResponse:
            def read(self):
                return json.dumps({"choices": [{"message": {"content": VERDICT}}]}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        def fake_urlopen(request, timeout=None):
            sent["url"] = request.full_url
            sent["headers"] = request.headers
            sent["body"] = json.loads(request.data.decode())
            return FakeResponse()

        findings = [dict(FINDINGS[0])]
        with mock.patch("urllib.request.urlopen", fake_urlopen):
            triage_findings(findings, config, log=lambda _m: None)
        return sent, findings

    def test_request_shape_and_verdict_applied(self):
        config = ScanConfig(
            ai_base_url="https://api.deepseek.com/v1", ai_model="deepseek-chat"
        )
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "k"}, clear=True):
            sent, findings = self._run(config)

        self.assertEqual(sent["url"], "https://api.deepseek.com/v1/chat/completions")
        self.assertEqual(sent["body"]["model"], "deepseek-chat")
        self.assertEqual([m["role"] for m in sent["body"]["messages"]], ["system", "user"])
        # Anthropic-only knobs must never reach a third-party endpoint.
        self.assertNotIn("output_config", sent["body"])
        self.assertEqual(findings[0]["ai_verdict"], "true_positive")
        self.assertEqual(findings[0]["score"], 65)

    def test_secret_value_is_masked_before_it_leaves(self):
        config = ScanConfig(ai_base_url="https://api.deepseek.com/v1")
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "k"}, clear=True):
            sent, _ = self._run(config)
        self.assertNotIn("f3a9c2b8e1d47650aa93", json.dumps(sent["body"]))

    def test_missing_key_raises_before_any_request(self):
        config = ScanConfig(ai_base_url="https://api.deepseek.com/v1")
        with mock.patch.dict("os.environ", NO_ENV, clear=True):
            with self.assertRaises(RuntimeError):
                triage_findings([dict(FINDINGS[0])], config, log=lambda _m: None)


# --- Anthropic path, against a stub SDK ------------------------------------


class _Block:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Response:
    stop_reason = "end_turn"

    def __init__(self):
        self.content = [_Block(VERDICT)]


@contextmanager
def fake_anthropic(record):
    """Install a stub `anthropic` module and capture the kwargs we send."""

    class Messages:
        def create(self, **kwargs):
            record.append(("plain", kwargs))
            return _Response()

    class BetaMessages:
        def create(self, **kwargs):
            record.append(("beta", kwargs))
            return _Response()

    class Beta:
        messages = BetaMessages()

    class Anthropic:
        def __init__(self, api_key=None, base_url=None):
            record.append(("init", {"base_url": base_url}))
            self.messages = Messages()
            self.beta = Beta()

    module = type(sys)("anthropic")
    module.Anthropic = Anthropic
    module.BadRequestError = type("BadRequestError", (Exception,), {})
    module.NotFoundError = type("NotFoundError", (Exception,), {})

    saved = sys.modules.get("anthropic")
    sys.modules["anthropic"] = module
    try:
        yield record
    finally:
        if saved is None:
            sys.modules.pop("anthropic", None)
        else:
            sys.modules["anthropic"] = saved


class TestAnthropicRequest(unittest.TestCase):
    def _run(self, config, env):
        record = []
        findings = [dict(FINDINGS[0])]
        with fake_anthropic(record), mock.patch.dict("os.environ", env, clear=True):
            triage_findings(findings, config, log=lambda _m: None)
        return record, findings

    def test_native_sends_the_anthropic_only_knobs(self):
        record, findings = self._run(ScanConfig(), {"ANTHROPIC_API_KEY": "k"})
        calls = [c for c in record if c[0] != "init"]
        self.assertEqual(calls[0][0], "beta")
        self.assertIn("output_config", calls[0][1])
        self.assertEqual(findings[0]["ai_verdict"], "true_positive")

    def test_compatible_endpoint_gets_a_plain_request(self):
        """Regression: `output_config` 400s on Moonshot and every batch failed."""
        config = ScanConfig(ai_base_url="https://api.moonshot.ai/anthropic", ai_model="kimi-k2")
        record, findings = self._run(config, {"ANTHROPIC_API_KEY": "k"})

        init = [c for c in record if c[0] == "init"][0][1]
        self.assertEqual(init["base_url"], "https://api.moonshot.ai/anthropic")

        calls = [c for c in record if c[0] != "init"]
        self.assertEqual(calls[0][0], "plain")
        self.assertNotIn("output_config", calls[0][1])
        self.assertEqual(calls[0][1]["model"], "kimi-k2")
        self.assertEqual(findings[0]["ai_verdict"], "true_positive")


if __name__ == "__main__":
    unittest.main()


class TestHeuristicIsPreserved(unittest.TestCase):
    """The model re-ranks the queue; it must not erase what scoring said.

    Without the original score there is no way to see the two signals
    disagree, and no way to undo a wrong dismissal.
    """

    def _triage(self, verdict, confidence, score=50):
        finding = {
            "repo": "a/b", "file": "api.go", "preview": "// @contact.url https://x.test/support",
            "pattern": "https://x.test/support", "score": score, "severity": "medium",
            "category": "all_url",
        }
        reply = json.dumps([{"id": 0, "verdict": verdict, "confidence": confidence, "reason": "r"}])

        class FakeResponse:
            def read(self_inner):
                return json.dumps({"choices": [{"message": {"content": reply}}]}).encode()

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *_):
                return False

        config = ScanConfig(ai_base_url="https://api.deepseek.com/v1")
        with mock.patch("urllib.request.urlopen", lambda *a, **k: FakeResponse()):
            with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "k"}, clear=True):
                triage_findings([finding], config, log=lambda _m: None)
        return finding

    def test_dismissal_keeps_the_original_score(self):
        finding = self._triage("false_positive", 95)
        self.assertEqual(finding["score"], 10)
        # 50 (medium) minus 40 lands below the low band: not a vulnerability.
        self.assertEqual(finding["severity"], "informative")
        self.assertEqual(finding["heuristic_score"], 50)
        self.assertEqual(finding["heuristic_severity"], "medium")

    def test_confirmation_keeps_the_original_score(self):
        finding = self._triage("true_positive", 90)
        self.assertEqual(finding["score"], 65)
        self.assertEqual(finding["heuristic_score"], 50)

    def test_low_confidence_moves_nothing(self):
        finding = self._triage("false_positive", 40)
        self.assertEqual(finding["score"], 50)
        self.assertEqual(finding["heuristic_score"], 50)
