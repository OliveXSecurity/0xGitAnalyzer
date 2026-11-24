"""Scan storage, and in particular deleting a scan.

Deleting used to be something you did with `rm`; it is a button in the
dashboard now, so the rules it relies on are worth pinning: the id names a
file inside the results directory and nothing else, a delete that finds
nothing says so instead of raising, and nothing but the one file goes.
"""

import json
import os
import shutil
import tempfile
import unittest

from gitanalyzer.store import ScanStore


def make_scan(scan_id: str, findings: int = 0) -> dict:
    return {
        "id": scan_id,
        "label": "test",
        "status": "completed",
        "started_at": "2026-11-23T00:00:0%dZ" % (findings % 10),
        "finished_at": "2026-11-23T00:01:00Z",
        "config": {"accounts": ["octocat"]},
        "stats": {"total_findings": findings},
        "findings": [{"file": "a.env"} for _ in range(findings)],
    }


class TestRoundTrip(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_store_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = ScanStore(self.dir)

    def test_save_load_and_list(self):
        self.store.save(make_scan("aaa", 2))
        self.store.save(make_scan("bbb", 5))
        self.assertEqual(self.store.load("aaa")["stats"]["total_findings"], 2)
        ids = [s["id"] for s in self.store.list_scans()]
        self.assertEqual(sorted(ids), ["aaa", "bbb"])

    def test_listing_skips_a_corrupt_file_instead_of_failing(self):
        self.store.save(make_scan("good"))
        with open(os.path.join(self.dir, "scan-broken.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual([s["id"] for s in self.store.list_scans()], ["good"])


class TestDelete(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="gitanalyzer_store_")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = ScanStore(self.dir)

    def test_delete_removes_the_file(self):
        path = self.store.save(make_scan("doomed"))
        self.assertTrue(self.store.delete("doomed"))
        self.assertFalse(os.path.exists(path))
        self.assertIsNone(self.store.load("doomed"))

    def test_deleting_twice_reports_that_it_was_already_gone(self):
        self.store.save(make_scan("doomed"))
        self.assertTrue(self.store.delete("doomed"))
        self.assertFalse(self.store.delete("doomed"))

    def test_deleting_an_unknown_scan_is_not_an_error(self):
        self.assertFalse(self.store.delete("never-existed"))

    def test_only_the_named_scan_goes(self):
        self.store.save(make_scan("keep", 3))
        self.store.save(make_scan("drop", 1))
        self.store.record_account("octocat", repos=2, findings=3)
        self.store.delete("drop")
        self.assertEqual([s["id"] for s in self.store.list_scans()], ["keep"])
        self.assertIn("octocat", self.store.load_history())

    def test_an_id_cannot_point_outside_the_results_directory(self):
        """The id arrives from a URL, so it must not be able to name a path.

        `path_for` keeps only characters a scan id can contain, which turns a
        traversal attempt into an ordinary (missing) file name inside the
        results directory.
        """
        outside = os.path.join(os.path.dirname(self.dir), "precious.json")
        with open(outside, "w", encoding="utf-8") as fh:
            json.dump({"keep": True}, fh)
        self.addCleanup(os.unlink, outside)

        for evil in ("../precious", "../../etc/passwd", "/etc/passwd", "..%2Fprecious"):
            self.assertFalse(self.store.delete(evil))
            target = self.store.path_for(evil)
            self.assertEqual(os.path.dirname(target), self.store.dir)
        self.assertTrue(os.path.exists(outside))


if __name__ == "__main__":
    unittest.main()
