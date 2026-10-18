"""Testovi za redflag_domains.py. Pokretanje:

    python -m unittest -v test_redflag_domains

Opcioni live test (stvarna mreza, samo GET):
    REDFLAG_LIVE=1 python -m unittest -v test_redflag_domains.LiveTest
"""
import os
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import closing
from unittest import mock

import requests

import redflag_domains as rf

SAMPLE = """[Adblock Plus 2.0]
! Title: uzorak
||ads.example.com^$third-party
||tracker.net^
||BRIGHT.Example.COM^
||tracker.net^
||0.0.0.1^
||brightdata.com^$third-party
||doc.example.org^$document
||only-script.example.com^$script,third-party
||restricted.example.net^$domain=~example.org
||notcaret.example.com
||withpath.example.com/ads^
||wild*.example.com^
##.banner-ad
example.org##div.ad
@@||allowed.example.com^
||allowed.example.com^
@@||scoped.example.com^$script
||scoped.example.com^
/adframe/*
"""


class FakeResp:
    def __init__(self, status=200, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}


def txt(domains):
    return ("\n".join("||%s^" % d for d in domains)).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dbp = os.path.join(self.tmp.name, "d.db")
        self.arp = os.path.join(self.tmp.name, "a.db")
        self.db = rf.DomainDatabase(self.dbp)


class NormalizeTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(rf.normalize_domain("Ads.Example.COM."), "ads.example.com")
        self.assertEqual(rf.normalize_domain("bücher.example"), "xn--bcher-kva.example")

    def test_invalid(self):
        for bad in ["", "com", "0.0.0.1", "::1", "a..b.com", "-a.com", "a-.com",
                    "a_b.com", "x" * 64 + ".com", "a" * 250 + ".com", None, 5]:
            self.assertIsNone(rf.normalize_domain(bad), repr(bad))


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.entries, self.stats = rf.EasyListParser.parse_with_stats(
            SAMPLE, "S", "tracker")
        self.domains = {e["domain"] for e in self.entries}

    def test_accepted(self):
        self.assertEqual(self.domains, {
            "ads.example.com", "tracker.net", "bright.example.com",
            "brightdata.com", "doc.example.org", "scoped.example.com"})

    def test_rejected_kinds(self):
        for d in ["0.0.0.1", "only-script.example.com", "restricted.example.net",
                  "notcaret.example.com", "withpath.example.com"]:
            self.assertNotIn(d, self.domains)

    def test_exception_removes_bare_only(self):
        self.assertNotIn("allowed.example.com", self.domains)
        self.assertIn("scoped.example.com", self.domains)  # izuzetak s $script ne vazi
        self.assertEqual(self.stats["removed_by_exception"], 1)

    def test_dedupe_and_lowercase(self):
        self.assertEqual(
            len([e for e in self.entries if e["domain"] == "tracker.net"]), 1)

    def test_stats_consistent(self):
        s = self.stats
        self.assertEqual(s["accepted"], len(self.entries))
        self.assertGreater(s["skipped"]["options"], 0)
        self.assertGreater(s["skipped"]["cosmetic"], 0)


@unittest.skipIf(rf._PSL is None, "tldextract nije instaliran (pip install tldextract)")
class PublicSuffixTest(unittest.TestCase):
    def test_suffix_entries_dropped_by_parser(self):
        text = "||co.uk^\n||bbc.co.uk^\n||ads.example.com^\n||github.io^\n"
        entries, stats = rf.EasyListParser.parse_with_stats(text, "S")
        got = {e["domain"] for e in entries}
        self.assertNotIn("co.uk", got)
        self.assertEqual(got, {"bbc.co.uk", "ads.example.com", "github.io"})
        self.assertEqual(stats["skipped"]["public_suffix"], 1)
        self.assertTrue(stats["psl_guard"])


class DatabaseTest(Base):
    def _load(self, source, domains):
        self.db.replace_source(source, [
            {"domain": d, "category": "tracker"} for d in domains],
            {"etag": None, "last_modified": None, "content_sha256": "x"})

    def test_subdomain_match_and_boundaries(self):
        self._load("S", ["ads.example.com"])
        r = self.db.check_domain("sub.deep.ads.example.com")
        self.assertTrue(r["found"])
        self.assertEqual(r["matched_rule"], "ads.example.com")
        self.assertFalse(self.db.check_domain("xads.example.com")["found"])
        self.assertFalse(self.db.check_domain("example.com")["found"])
        self.assertFalse(self.db.check_domain("com")["found"])
        self.assertEqual(self.db.check_domain("1.2.3.4")["reason"], "invalid_domain")

    def test_most_specific_wins_and_multi_source(self):
        self._load("A", ["example.com"])
        self._load("B", ["ads.example.com"])
        r = self.db.check_domain("x.ads.example.com")
        self.assertEqual(r["matched_rule"], "ads.example.com")
        self._load("C", ["ads.example.com"])
        r = self.db.check_domain("ads.example.com")
        self.assertEqual({m["source"] for m in r["matches"]}, {"B", "C"})

    def test_replace_removes_stale(self):
        self._load("S", ["a.example.com", "b.example.com"])
        self._load("S", ["a.example.com"])
        self.assertFalse(self.db.check_domain("b.example.com")["found"])
        self.assertEqual(self.db.get_stats()["total"], 1)

    def test_known_limitation_public_suffix(self):
        """Baza sama NE filtrira sufikse (to radi parser uz tldextract)."""
        self._load("S", ["co.uk"])
        self.assertTrue(self.db.check_domain("bbc.co.uk")["found"])

    def test_state_persists_across_reopen(self):
        self.db.replace_source("S", [], {"etag": '"e1"', "last_modified": "lm",
                                         "content_sha256": "h"})
        st = rf.DomainDatabase(self.dbp).get_source_state("S")
        self.assertEqual((st["etag"], st["content_sha256"]), ('"e1"', "h"))

    def test_concurrent_access(self):
        self._load("S", ["a.example.com"])
        errors = []

        def reader():
            try:
                for _ in range(200):
                    self.db.check_domain("a.example.com")
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                for i in range(50):
                    self._load("S", ["a.example.com", "n%d.example.com" % i])
            except Exception as e:
                errors.append(e)

        ts = [threading.Thread(target=reader) for _ in range(4)] + \
             [threading.Thread(target=writer)]
        [t.start() for t in ts]
        [t.join(30) for t in ts]
        self.assertEqual(errors, [])


class FetchTest(Base):
    def src(self, **kw):
        return rf.ExternalSource("S", "https://example.invalid/list.txt", **kw)

    def run_fetch(self, source, resp):
        with mock.patch.object(rf.requests, "get", return_value=resp) as g:
            return source.fetch_if_updated(self.db), g

    def test_first_fetch_without_validators_still_fetches(self):
        """Regresija: stari kod nikad nije preuzeo izvor bez ETag/Last-Modified."""
        res, _ = self.run_fetch(self.src(), FakeResp(200, txt(["a.example.com"])))
        self.assertEqual(res["status"], "updated")
        self.assertTrue(self.db.check_domain("a.example.com")["found"])

    def test_unchanged_by_hash_without_validators(self):
        s = self.src()
        self.run_fetch(s, FakeResp(200, txt(["a.example.com"])))
        res, _ = self.run_fetch(s, FakeResp(200, txt(["a.example.com"])))
        self.assertEqual(res["status"], "unchanged")

    def test_conditional_headers_and_304(self):
        s = self.src()
        self.run_fetch(s, FakeResp(200, txt(["a.example.com"]),
                                   {"ETag": '"v1"', "Last-Modified": "Mon"}))
        res, g = self.run_fetch(s, FakeResp(304))
        sent = g.call_args.kwargs["headers"]
        self.assertEqual(sent["If-None-Match"], '"v1"')
        self.assertEqual(sent["If-Modified-Since"], "Mon")
        self.assertEqual(res["status"], "not_modified")
        self.assertTrue(self.db.check_domain("a.example.com")["found"])

    def test_change_replaces_content(self):
        s = self.src()
        self.run_fetch(s, FakeResp(200, txt(["a.example.com", "b.example.com"])))
        res, _ = self.run_fetch(s, FakeResp(200, txt(["a.example.com", "c.example.com"])))
        self.assertEqual(res["status"], "updated")
        self.assertFalse(self.db.check_domain("b.example.com")["found"])
        self.assertTrue(self.db.check_domain("c.example.com")["found"])

    def test_empty_parse_rejected_keeps_old(self):
        s = self.src()
        self.run_fetch(s, FakeResp(200, txt(["a.example.com"])))
        res, _ = self.run_fetch(s, FakeResp(200, b"<html>Just a moment...</html>"))
        self.assertEqual(res["status"], "rejected")
        self.assertTrue(self.db.check_domain("a.example.com")["found"])

    def test_shrink_rejected(self):
        s = self.src()
        big = ["d%d.example.com" % i for i in range(100)]
        self.run_fetch(s, FakeResp(200, txt(big)))
        res, _ = self.run_fetch(s, FakeResp(200, txt(big[:10])))
        self.assertEqual(res["status"], "rejected")
        self.assertEqual(self.db.get_stats()["total"], 100)

    def test_force_accepts_shrink(self):
        s = self.src()
        big = ["d%d.example.com" % i for i in range(100)]
        self.run_fetch(s, FakeResp(200, txt(big)))
        with mock.patch.object(rf.requests, "get",
                               return_value=FakeResp(200, txt(big[:10]))):
            res = s.fetch_if_updated(self.db, force=True)
        self.assertEqual(res["status"], "updated")
        self.assertEqual(self.db.get_stats()["total"], 10)

    def test_http_error_and_exception_keep_state(self):
        s = self.src()
        res, _ = self.run_fetch(s, FakeResp(500))
        self.assertEqual(res["status"], "error")
        with mock.patch.object(rf.requests, "get",
                               side_effect=requests.ConnectionError("x")):
            res = s.fetch_if_updated(self.db)
        self.assertEqual(res["status"], "error")
        self.assertIsNone(self.db.get_source_state("S"))

    def test_oversize_rejected(self):
        s = self.src()
        s.MAX_BYTES = 10
        res, _ = self.run_fetch(s, FakeResp(200, txt(["a.example.com"])))
        self.assertEqual(res["status"], "rejected")


class SchedulerTest(Base):
    def test_one_source_failing_does_not_stop_others(self):
        bad = mock.Mock(name_="bad")
        bad.name = "bad"
        bad.fetch_if_updated.side_effect = RuntimeError("boom")
        good = rf.ExternalSource("good", "https://example.invalid/g.txt")
        sch = rf.UpdateScheduler(self.db, [bad, good])
        with mock.patch.object(rf.requests, "get",
                               return_value=FakeResp(200, txt(["a.example.com"]))):
            res = sch.run_once()
        self.assertEqual([r["status"] for r in res], ["error", "updated"])

    def test_first_update_immediate_and_stop_is_fast(self):
        good = rf.ExternalSource("good", "https://example.invalid/g.txt")
        sch = rf.UpdateScheduler(self.db, [good], interval_hours=3)
        with mock.patch.object(rf.requests, "get",
                               return_value=FakeResp(200, txt(["a.example.com"]))):
            sch.start()
            t0 = time.time()
            while not sch.last_results and time.time() - t0 < 5:
                time.sleep(0.05)
            self.assertTrue(sch.last_results, "prvo azuriranje nije bilo odmah")
            t1 = time.time()
            sch.stop()
        self.assertLess(time.time() - t1, 2)
        self.assertFalse(sch._thread.is_alive())

    def test_retry_sooner_when_all_failed(self):
        class FakeStop:
            def __init__(self):
                self.waits = []

            def is_set(self):
                return bool(self.waits)

            def wait(self, t):
                self.waits.append(t)
                return False

        sch = rf.UpdateScheduler(self.db, [], interval_hours=3)
        sch.run_once = lambda: [{"status": "error"}]
        sch._stop = FakeStop()
        sch._loop()
        self.assertEqual(sch._stop.waits, [300])

    def test_loop_survives_exception(self):
        class FakeStop:
            def __init__(self):
                self.n = 0

            def is_set(self):
                return self.n >= 2

            def wait(self, t):
                self.n += 1
                return False

        sch = rf.UpdateScheduler(self.db, [], interval_hours=3)
        calls = []

        def boom():
            calls.append(1)
            raise ValueError("x")

        sch.run_once = boom
        sch._stop = FakeStop()
        sch._loop()
        self.assertEqual(len(calls), 2)

    def test_no_telemetry_only_get_to_configured_urls(self):
        rec = []

        def fake_get(url, **kw):
            rec.append(("GET", url))
            return FakeResp(200, txt(["a.example.com"]))

        def forbid(name):
            def f(*a, **k):
                rec.append((name, a))
                raise AssertionError(name)
            return f

        s = rf.ExternalSource("S", "https://example.invalid/list.txt")
        with mock.patch.object(rf.requests, "get", fake_get), \
             mock.patch.object(rf.requests, "post", forbid("POST")), \
             mock.patch.object(rf.requests, "put", forbid("PUT")), \
             mock.patch.object(rf.requests, "request", forbid("REQUEST")), \
             mock.patch.object(rf.requests, "Session", forbid("SESSION")):
            sch = rf.UpdateScheduler(self.db, [s])
            sch.run_once()
            sch.run_once()
        self.assertTrue(all(m == "GET" and u == s.url for m, u in rec), rec)

    def test_source_code_has_no_outbound_writes(self):
        with open(rf.__file__, encoding="utf-8") as f:
            src = f.read()
        for bad in ["requests.post", "requests.put", "requests.patch",
                    "requests.request", "urlopen", "socket.", "smtplib"]:
            self.assertNotIn(bad, src, bad)


class ArchiveAndPatternTest(Base):
    def setUp(self):
        super().setUp()
        self.ar = rf.LocalArchive(self.arp)
        self.pr = rf.PatternRecognition(self.ar)

    B64 = "QWxhZGRpbjpvcGVuIHNlc2FtZQ" * 4  # 104 znaka

    def test_benign_not_flagged(self):
        reqs = [
            {"method": "GET", "url": "https://shop.example/p?utm_source=a&utm_medium=b"
             "&utm_campaign=c&utm_term=d&utm_content=e&ref=1&x=2&y=3&z=4&a=5&b=6&c=7&d=8"},
            {"method": "GET", "url": "https://x.example/?language=en"},
            {"method": "POST", "url": "https://up.example/upload", "body": "x" * 20000},
        ]
        r = self.pr.analyze_domain_behavior("shop.example", reqs)
        self.assertEqual(r["status"], "no_signal")
        self.assertEqual(self.ar.list_recent(), [])

    def test_two_signatures_not_enough(self):
        reqs = [{"method": "POST", "url": "https://t.example/?d=" + self.B64,
                 "body": "x" * 20000}]
        r = self.pr.analyze_domain_behavior("t.example", reqs)
        self.assertEqual(sorted(r["flags"]), ["base64_in_url", "large_post"])
        self.assertEqual(r["status"], "no_signal")

    def test_three_signatures_flagged_and_archived(self):
        reqs = [
            {"method": "POST", "url": "https://t.example/c?screen=1&timezone=2&platform=3",
             "body": "x" * 20000, "cookies": [{"name": "i", "max_age": 3 * 365 * 86400}]},
        ]
        r = self.pr.analyze_domain_behavior("t.example", reqs)
        self.assertEqual(r["status"], "suspicious")
        rec = self.ar.list_recent()
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["domain"], "t.example")

    def test_fingerprint_needs_three_keys(self):
        self.assertFalse(rf.PatternRecognition._fingerprint_params(
            {"url": "https://a.example/?screen=1&timezone=2"}))
        self.assertTrue(rf.PatternRecognition._fingerprint_params(
            {"url": "https://a.example/?screen=1&timezone=2&canvas=x"}))

    def test_prune(self):
        self.ar.add_detection("new.example", "t", {})
        with closing(sqlite3.connect(self.arp)) as c, c:
            c.execute("INSERT INTO detections (domain, detection_type, evidence,"
                      " detected_at) VALUES ('old.example','t','{}',"
                      "'2020-01-01T00:00:00+00:00')")
        self.assertEqual(self.ar.prune(90), 1)
        self.assertEqual([d["domain"] for d in self.ar.list_recent()], ["new.example"])


@unittest.skipUnless(os.environ.get("REDFLAG_LIVE") == "1", "REDFLAG_LIVE=1 nije postavljen")
class LiveTest(Base):
    def test_live_github_sources(self):
        sch = rf.UpdateScheduler(self.db, rf.build_sources("github"))
        r1 = sch.run_once()
        for r in r1:
            self.assertEqual(r["status"], "updated", r)
            self.assertGreater(r["entries"], 20, r)
        r2 = sch.run_once()
        for r in r2:
            self.assertIn(r["status"], ("not_modified", "unchanged"), r)
        self.assertGreater(self.db.get_stats()["total"], 1000)
        print("\nLIVE stats:", self.db.get_stats())
        print("LIVE parse stats:", [r["stats"] for r in r1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
