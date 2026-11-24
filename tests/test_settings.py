"""Settings storage, and the rule that tokens never leak.

A scan file is something you hand to a client. A token must never reach one,
and the HTTP API must never hand a stored token back to the browser.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest

from gitanalyzer import settings as st
from gitanalyzer.config import ScanConfig


class TestMask(unittest.TestCase):
    def test_hint_is_not_the_token(self):
        token = "ghp_abcdefghijklmnopqrstuvwxyz"
        hint = st.mask_secret(token)
        self.assertNotIn("efghijklmnopqrstuv", hint)
        self.assertTrue(hint.startswith("ghp_"))
        self.assertTrue(hint.endswith(token[-4:]))

    def test_short_values_are_fully_hidden(self):
        self.assertEqual(st.mask_secret("abc"), "***")
        self.assertEqual(st.mask_secret(""), "")


class TestStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_set_")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_defaults_when_nothing_is_stored(self):
        self.assertEqual(st.load(self.dir), dict(st.DEFAULTS))

    def test_the_shipped_limits_are_off(self):
        """0 everywhere: a limit nobody set must not empty a scan."""
        for key in ("max_repo_age_months", "max_repo_size_mb",
                    "rescan_days", "max_findings_per_repo"):
            self.assertEqual(st.DEFAULTS[key], 0, key)

    def test_round_trip(self):
        st.save(self.dir, dict(st.DEFAULTS, keywords=["acme"], github_token="ghp_x"))
        self.assertEqual(st.load(self.dir)["keywords"], ["acme"])

    def test_file_is_owner_only(self):
        """It may hold a token, so it must not be world-readable."""
        st.save(self.dir, dict(st.DEFAULTS, github_token="ghp_secret"))
        mode = os.stat(st.path_for(self.dir)).st_mode
        self.assertFalse(mode & stat.S_IRGRP, oct(mode))
        self.assertFalse(mode & stat.S_IROTH, oct(mode))

    def test_corrupt_file_falls_back_to_defaults(self):
        with open(st.path_for(self.dir), "w", encoding="utf-8") as handle:
            handle.write("{ not json")
        self.assertEqual(st.load(self.dir), dict(st.DEFAULTS))

    def test_unknown_keys_are_not_stored(self):
        st.save(self.dir, dict(st.DEFAULTS, surprise="x"))
        with open(st.path_for(self.dir), encoding="utf-8") as handle:
            self.assertNotIn("surprise", json.load(handle))


class TestMerge(unittest.TestCase):
    def test_absent_secret_is_preserved(self):
        """Saving the form without retyping the token must not wipe it."""
        current = dict(st.DEFAULTS, github_token="ghp_keepme")
        merged = st.merge(current, {"keywords": ["acme"]})
        self.assertEqual(merged["github_token"], "ghp_keepme")
        self.assertEqual(merged["keywords"], ["acme"])

    def test_empty_string_clears_a_secret(self):
        current = dict(st.DEFAULTS, github_token="ghp_keepme")
        self.assertEqual(st.merge(current, {"github_token": ""})["github_token"], "")

    def test_null_secret_is_ignored(self):
        current = dict(st.DEFAULTS, ai_key="sk-x")
        self.assertEqual(st.merge(current, {"ai_key": None})["ai_key"], "sk-x")


class TestLeakage(unittest.TestCase):
    SECRETS = dict(st.DEFAULTS, github_token="ghp_SECRETVALUE1234", ai_key="sk-SECRETVALUE1234")

    def test_public_never_contains_a_token(self):
        blob = json.dumps(st.public(self.SECRETS))
        self.assertNotIn("ghp_SECRETVALUE1234", blob)
        self.assertNotIn("sk-SECRETVALUE1234", blob)

    def test_public_still_reports_that_one_is_set(self):
        out = st.public(self.SECRETS)
        self.assertTrue(out["github_token_set"])
        self.assertTrue(out["ai_key_set"])
        self.assertTrue(out["github_token_hint"])

    def test_scan_defaults_carry_no_secrets(self):
        """These keys become ScanConfig, which is written into every scan."""
        blob = json.dumps(st.scan_defaults(self.SECRETS))
        self.assertNotIn("ghp_SECRETVALUE1234", blob)
        self.assertNotIn("sk-SECRETVALUE1234", blob)
        for field in st.SECRET_FIELDS:
            self.assertNotIn(field, st.scan_defaults(self.SECRETS))

    def test_a_config_built_from_settings_serialises_without_secrets(self):
        config = ScanConfig.from_dict(st.scan_defaults(self.SECRETS))
        self.assertNotIn("SECRETVALUE", json.dumps(config.to_dict()))

    def test_secrets_helper_returns_them_separately(self):
        out = st.secrets(self.SECRETS)
        self.assertEqual(out["github_token"], "ghp_SECRETVALUE1234")
        self.assertEqual(out["ai_key"], "sk-SECRETVALUE1234")


class TestProviders(unittest.TestCase):
    def test_every_provider_is_well_formed(self):
        for provider in st.PROVIDERS:
            self.assertIn(provider["api"], ("anthropic", "openai"), provider["id"])
            self.assertTrue(provider["label"])
            self.assertIsInstance(provider["models"], list)

    def test_choosing_a_provider_fills_endpoint_and_format(self):
        out = st.apply_provider(dict(st.DEFAULTS, ai_provider="deepseek"))
        self.assertEqual(out["ai_base_url"], "https://api.deepseek.com/v1")
        self.assertEqual(out["ai_api"], "openai")

    def test_custom_provider_keeps_whatever_was_typed(self):
        out = st.apply_provider(
            dict(st.DEFAULTS, ai_provider="custom", ai_base_url="https://gw.example/v1")
        )
        self.assertEqual(out["ai_base_url"], "https://gw.example/v1")

    def test_anthropic_models_are_listed(self):
        self.assertIn("claude-opus-5-5", st.PROVIDER_BY_ID["anthropic"]["models"])


class TestKeyPrecedence(unittest.TestCase):
    def test_a_key_from_settings_beats_the_environment(self):
        from unittest import mock

        from gitanalyzer.triage import resolve_provider

        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": "from-env"}, clear=True):
            provider = resolve_provider(ScanConfig(), api_key="from-settings")
        self.assertEqual(provider.key, "from-settings")
        self.assertEqual(provider.key_env, "settings")


if __name__ == "__main__":
    unittest.main()


class TestEverythingIsConfigurable(unittest.TestCase):
    """The panel claims to expose every scan setting. Check it actually can."""

    def test_scan_defaults_cover_the_config(self):
        missing = set(ScanConfig().to_dict()) - set(st.scan_defaults(st.DEFAULTS))
        # Only these are per-run or resolved elsewhere, never panel defaults.
        allowed = {"accounts", "label", "ai_key_env"}
        self.assertEqual(missing - allowed, set(), "not reachable from the panel: %s" % (missing - allowed))

    def test_tuning_fields_reach_the_config(self):
        data = dict(st.DEFAULTS,
                    wordlists={"exclude_globs": ["vendor/**"]},
                    ai_system_prompt="judge harshly",
                    clone_depth=1)
        config = ScanConfig.from_dict(st.scan_defaults(data))
        self.assertEqual(config.wordlists, {"exclude_globs": ["vendor/**"]})
        self.assertEqual(config.ai_system_prompt, "judge harshly")
        self.assertEqual(config.clone_depth, 1)


class TestWordlistOverrides(unittest.TestCase):
    """Every list in patterns.py can be replaced from the panel."""

    def test_every_list_is_editable_and_round_trips(self):
        from gitanalyzer.patterns import WORDLIST_FIELDS, Wordlists, builtin_wordlists

        payload = {name: ["only-this"] for name in WORDLIST_FIELDS}
        stored = st.clean_wordlists(payload)
        self.assertEqual(sorted(stored), sorted(WORDLIST_FIELDS))
        resolved = Wordlists.resolve(stored)
        for name in WORDLIST_FIELDS:
            self.assertEqual(getattr(resolved, name), ["only-this"], name)
        # and nothing was taken from the built-in lists
        self.assertNotEqual(getattr(resolved, "rg_patterns"), builtin_wordlists()["rg_patterns"])

    def test_an_empty_list_means_the_built_in_one(self):
        from gitanalyzer.patterns import Wordlists, builtin_wordlists

        self.assertEqual(st.clean_wordlists({"include_globs": []}), {})
        resolved = Wordlists.resolve({"include_globs": [], "exclude_globs": ["   "]})
        self.assertEqual(resolved.include_globs, builtin_wordlists()["include_globs"])
        self.assertEqual(resolved.exclude_globs, builtin_wordlists()["exclude_globs"])

    def test_unknown_lists_and_junk_are_ignored(self):
        self.assertEqual(st.clean_wordlists({"rm_rf": ["x"], "rg_patterns": "not-a-list"}), {})
        self.assertEqual(st.clean_wordlists("nonsense"), {})

    def test_a_regex_keeps_its_trailing_space_but_a_glob_does_not(self):
        cleaned = st.clean_wordlists({"rg_patterns": ["foo "], "include_globs": [" *.py "]})
        self.assertEqual(cleaned["rg_patterns"], ["foo "])
        self.assertEqual(cleaned["include_globs"], ["*.py"])

    def test_placeholder_override_drops_a_match(self):
        from gitanalyzer.patterns import Wordlists, is_placeholder

        value = "acme-demo-key-7f3a9c2b"
        self.assertFalse(is_placeholder(value))
        custom = Wordlists.resolve({"placeholder_contains": ["acme-demo"]})
        self.assertTrue(is_placeholder(value, custom))
        self.assertFalse(is_placeholder("f3a9c2b8e1d47650aa93", custom))

    def test_detector_tiers_are_editable_and_case_insensitive(self):
        from gitanalyzer.patterns import Wordlists
        from gitanalyzer.scoring import score_finding

        lists = Wordlists.resolve({"low_value_detectors": ["Acme Widgets"]})
        scored = score_finding("x" * 20, "src/app.py", "k=1", "trufflehog", False, "acmewidgets", lists)
        plain = score_finding("x" * 20, "src/app.py", "k=1", "trufflehog", False, "acmewidgets")
        self.assertEqual(plain - scored, 40)

    def test_diff_reports_only_what_changed(self):
        from gitanalyzer.patterns import Wordlists

        self.assertEqual(Wordlists().diff(), {})
        self.assertEqual(Wordlists.resolve({"include_globs": ["*.py"]}).diff(),
                         {"include_globs": ["*.py"]})

    def test_custom_prompt_replaces_the_built_in_one(self):
        from gitanalyzer.triage import SYSTEM_PROMPT, system_prompt

        self.assertEqual(system_prompt(ScanConfig()), SYSTEM_PROMPT)
        self.assertEqual(system_prompt(ScanConfig(ai_system_prompt="  mine  ")), "mine")
