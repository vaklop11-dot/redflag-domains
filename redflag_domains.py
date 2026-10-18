#!/usr/bin/env python3
"""RedFlag Domain Intelligence - test paket v0.2

Samo stdlib + requests. Nema UI-a, nema hvatanja saobracaja.

NAMJERNO NE POSTOJI: slanje detekcija ili ikakvih podataka van uredjaja.
Jedini izlazni zahtjevi su HTTP GET prema URL-ovima izvora (SOURCE_SETS).
Izvori vide IP adresu i vrijeme zahtjeva; to je stvarna granica "zero-knowledge".

PatternRecognition je samo sucelje + heuristike: ovaj paket ne sadrzi nikakav
izvor mrezne telemetrije. Ulaz (lista zahtjeva) mora doci izvana.
"""

import argparse
import base64
import hashlib
import ipaddress
import logging
import os
import re
import sqlite3
import sys
import threading
from contextlib import closing
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

import requests

try:  # opciono: zastita od unosa koji su javni sufiksi (npr. 'co.uk')
    import tldextract
    _PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except Exception:  # pragma: no cover
    _PSL = None

log = logging.getLogger("redflag")

VERSION = "0.2.0"
USER_AGENT = "RedFlagDomainBot/%s (+kontakt: %s)" % (
    VERSION, os.environ.get("REDFLAG_CONTACT", "NIJE-POSTAVLJENO"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------- domene

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(host):
    """Vraca normalizovanu domenu ili None (IP adrese, jedna labela, nevazece)."""
    if not isinstance(host, str):
        return None
    h = host.strip().lower().rstrip(".")
    if not h or len(h) > 253:
        return None
    try:
        h = h.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    try:
        ipaddress.ip_address(h)
        return None
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        return None
    return h


def is_public_suffix(domain):
    """True ako je domena sama javni sufiks (npr. 'co.uk'). Bez tldextract: False.

    Koristi ugradjeni snapshot PSL-a (bez mreze). Starost snapshota: NEMAM POTVRDU.
    Privatni sufiksi (github.io, blogspot.com) se NE tretiraju kao sufiksi.
    """
    if _PSL is None:
        return False
    e = _PSL(domain)
    return e.domain == "" and e.suffix != ""


def registrable_domain(name):
    """(registrovana_domena, tacno). Bez tldextract: aproksimacija = zadnje 2
    labele (pogresno za 'x.co.uk'), a 'tacno' je False. None = sam sufiks/nevazece."""
    labels = name.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return None, False
    if _PSL is not None:
        e = _PSL(name)
        if e.domain and e.suffix:
            return e.domain + "." + e.suffix, True
        return None, True
    return ".".join(labels[-2:]), False


# ---------------------------------------------------------------- parser

class EasyListParser:
    """Izdvaja SAMO ||domena^ pravila (opciono uz $third-party / $document).

    Sve ostalo se preskace i broji: putanje, wildcard, kozmeticka pravila,
    pravila s ogranicenjima ($domain=, $script, $image, ...), IP adrese.
    Izuzeci (@@||domena^) uklanjaju tu domenu iz rezultata.
    """

    ALLOWED_OPTIONS = {"third-party", "3p", "document"}
    _BLOCK = re.compile(r"^\|\|([a-z0-9._-]+)\^(?:\$(.+))?$", re.I)
    _EXCEPT = re.compile(r"^@@\|\|([a-z0-9._-]+)\^(?:\$(.+))?$", re.I)

    @classmethod
    def parse_with_stats(cls, text, source_name, category="tracker"):
        skipped = {"comment": 0, "cosmetic": 0, "path_or_other": 0,
                   "options": 0, "invalid_host": 0, "exception_other": 0,
                   "public_suffix": 0}
        found, exceptions = {}, set()
        total = 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            total += 1
            if line.startswith(("!", "[")):
                skipped["comment"] += 1
                continue
            if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line:
                skipped["cosmetic"] += 1
                continue
            if line.startswith("@@"):
                m = cls._EXCEPT.match(line)
                opts = cls._opts(m.group(2)) if m else None
                if m and opts is not None and opts <= cls.ALLOWED_OPTIONS:
                    d = normalize_domain(m.group(1))
                    if d:
                        exceptions.add(d)
                else:
                    skipped["exception_other"] += 1
                continue
            m = cls._BLOCK.match(line)
            if not m:
                skipped["path_or_other"] += 1
                continue
            opts = cls._opts(m.group(2))
            if not opts <= cls.ALLOWED_OPTIONS:
                skipped["options"] += 1
                continue
            d = normalize_domain(m.group(1))
            if d is None:
                skipped["invalid_host"] += 1
                continue
            if is_public_suffix(d):
                skipped["public_suffix"] += 1
                continue
            found[d] = {"domain": d, "category": category,
                        "source": source_name, "risk_level": "medium"}
        removed = [d for d in found if d in exceptions]
        for d in removed:
            del found[d]
        stats = {"lines": total, "accepted": len(found),
                 "removed_by_exception": len(removed), "skipped": skipped,
                 "psl_guard": _PSL is not None}
        return list(found.values()), stats

    @classmethod
    def parse(cls, text, source_name, category="tracker"):
        return cls.parse_with_stats(text, source_name, category)[0]

    @staticmethod
    def _opts(s):
        if not s:
            return set()
        return {o.strip().lower() for o in s.split(",") if o.strip()}


# ---------------------------------------------------------------- baza

class DomainDatabase:
    """Lokalna SQLite baza domena. Zamjena po izvoru, nikad slanje van."""

    def __init__(self, db_path="redflag_domains.db"):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path, timeout=30)

    def _init_db(self):
        with self.lock, closing(self._connect()) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS domains (
                domain TEXT NOT NULL, category TEXT NOT NULL,
                source TEXT NOT NULL, added_at TEXT NOT NULL,
                risk_level TEXT NOT NULL, PRIMARY KEY (domain, source))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS source_state (
                source TEXT PRIMARY KEY, etag TEXT, last_modified TEXT,
                content_sha256 TEXT, last_checked_utc TEXT,
                last_changed_utc TEXT, entry_count INTEGER NOT NULL DEFAULT 0)""")

    def replace_source(self, source, entries, state):
        """Atomarno: obrisi stare unose izvora, upisi nove, spremi stanje."""
        now = utc_now()
        rows = [(e["domain"], e.get("category", "unknown"), source, now,
                 e.get("risk_level", "medium")) for e in entries]
        with self.lock, closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM domains WHERE source=?", (source,))
            conn.executemany(
                "INSERT OR REPLACE INTO domains VALUES (?,?,?,?,?)", rows)
            conn.execute(
                """INSERT OR REPLACE INTO source_state
                   (source, etag, last_modified, content_sha256,
                    last_checked_utc, last_changed_utc, entry_count)
                   VALUES (?,?,?,?,?,?,?)""",
                (source, state.get("etag"), state.get("last_modified"),
                 state.get("content_sha256"), now, now, len(rows)))

    def touch_source(self, source, etag=None, last_modified=None):
        with self.lock, closing(self._connect()) as conn, conn:
            conn.execute(
                """UPDATE source_state SET last_checked_utc=?,
                   etag=COALESCE(?, etag),
                   last_modified=COALESCE(?, last_modified)
                   WHERE source=?""",
                (utc_now(), etag, last_modified, source))

    def get_source_state(self, source):
        with self.lock, closing(self._connect()) as conn:
            row = conn.execute(
                """SELECT etag, last_modified, content_sha256,
                          last_checked_utc, last_changed_utc, entry_count
                   FROM source_state WHERE source=?""", (source,)).fetchone()
        if not row:
            return None
        keys = ("etag", "last_modified", "content_sha256",
                "last_checked_utc", "last_changed_utc", "entry_count")
        return dict(zip(keys, row))

    def check_domain(self, host):
        """Provjerava domenu i sve njene nadredjene domene (bez samog TLD-a).

        OGRANICENJE: nema Public Suffix liste. Ako izvor sadrzi unos poput
        'co.uk', poklopit ce sve pod tim sufiksom.
        """
        d = normalize_domain(host)
        if d is None:
            return {"found": False, "reason": "invalid_domain"}
        labels = d.split(".")
        cands = [".".join(labels[i:]) for i in range(len(labels) - 1)]
        ph = ",".join("?" * len(cands))
        with self.lock, closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT domain, category, source, added_at, risk_level "
                "FROM domains WHERE domain IN (%s)" % ph, cands).fetchall()
        if not rows:
            return {"found": False, "queried": d}
        best = max((r[0] for r in rows), key=len)
        return {"found": True, "queried": d, "matched_rule": best,
                "matches": [{"category": r[1], "source": r[2],
                             "added_at": r[3], "risk_level": r[4]}
                            for r in rows if r[0] == best]}

    def get_stats(self):
        with self.lock, closing(self._connect()) as conn:
            total = conn.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
            by_cat = dict(conn.execute(
                "SELECT category, COUNT(*) FROM domains GROUP BY category"))
            by_src = dict(conn.execute(
                "SELECT source, COUNT(*) FROM domains GROUP BY source"))
        return {"total": total, "by_category": by_cat, "by_source": by_src}


# ---------------------------------------------------------------- izvori

class ExternalSource:
    """Read-only izvor. Uslovni GET (If-None-Match / If-Modified-Since),
    a kad izvor ne salje validatore, poredi SHA-256 sadrzaja.

    Zastita od losih ažuriranja (PRAGOVI NISU KALIBRISANI):
      - min_entries: prazan/pokvaren parse ne smije obrisati bazu
      - max_shrink: lista koja izgubi vise od 50% unosa se odbija
    SHA-256 ovdje je zapis porijekla i detekcija promjene, NE potpis izvora.
    """

    MAX_BYTES = 50 * 1024 * 1024

    def __init__(self, name, url, category="tracker",
                 parser=EasyListParser.parse_with_stats,
                 min_entries=1, max_shrink=0.5):
        self.name, self.url, self.category = name, url, category
        self.parser = parser
        self.min_entries, self.max_shrink = min_entries, max_shrink

    def fetch_if_updated(self, db, force=False):
        res = {"source": self.name, "status": None}
        state = db.get_source_state(self.name)
        headers = {"User-Agent": USER_AGENT,
                   "Accept": "text/plain,*/*;q=0.5"}
        if state:
            if state.get("etag"):
                headers["If-None-Match"] = state["etag"]
            if state.get("last_modified"):
                headers["If-Modified-Since"] = state["last_modified"]
        try:
            r = requests.get(self.url, headers=headers, timeout=30)
        except requests.RequestException as e:
            return dict(res, status="error", detail=str(e))
        if r.status_code == 304 and state:
            db.touch_source(self.name)
            return dict(res, status="not_modified")
        if r.status_code != 200:
            return dict(res, status="error", detail="HTTP %s" % r.status_code)
        body = r.content
        if len(body) > self.MAX_BYTES:
            return dict(res, status="rejected", detail="odgovor prevelik")
        sha = hashlib.sha256(body).hexdigest()
        etag = r.headers.get("ETag")
        lm = r.headers.get("Last-Modified")
        if state and state.get("content_sha256") == sha:
            db.touch_source(self.name, etag, lm)
            return dict(res, status="unchanged")
        entries, stats = self.parser(
            body.decode("utf-8", errors="replace"), self.name, self.category)
        prev = state["entry_count"] if state else 0
        if len(entries) < self.min_entries:
            return dict(res, status="rejected", stats=stats,
                        detail="premalo unosa (%d)" % len(entries))
        if (not force and prev > 0
                and len(entries) < prev * (1 - self.max_shrink)):
            return dict(res, status="rejected", stats=stats,
                        detail="lista se smanjila s %d na %d" %
                        (prev, len(entries)))
        db.replace_source(self.name, entries, {
            "etag": etag, "last_modified": lm, "content_sha256": sha})
        return dict(res, status="updated", entries=len(entries),
                    previous=prev, stats=stats, content_sha256=sha)


SOURCE_SETS = {
    # Provjereno dostupno i s ETag zaglavljem u sandboxu 2026-10-16
    "github": [
        ("EasyPrivacy-trackingservers", "tracker",
         "https://raw.githubusercontent.com/easylist/easylist/master/"
         "easyprivacy/easyprivacy_trackingservers.txt"),
        ("EasyList-adservers", "ad",
         "https://raw.githubusercontent.com/easylist/easylist/master/"
         "easylist/easylist_adservers.txt"),
    ],
    # NEMAM POTVRDU: tacan URL, preusmjeravanja ni zaglavlja nisu provjereni
    "easylist_to": [
        ("EasyList", "ad", "https://easylist.to/easylist/easylist.txt"),
        ("EasyPrivacy", "tracker", "https://easylist.to/easylist/easyprivacy.txt"),
    ],
}


def build_sources(set_name):
    names = ["github", "easylist_to"] if set_name == "all" else [set_name]
    return [ExternalSource(n, u, c) for s in names
            for (n, c, u) in SOURCE_SETS[s]]


# ---------------------------------------------------------------- scheduler

class UpdateScheduler:
    """Ažurira bazu svakih interval_hours (default 3). Prvo ažuriranje odmah."""

    def __init__(self, domain_db, external_sources, interval_hours=3.0):
        self.db = domain_db
        self.sources = external_sources
        self.interval_seconds = interval_hours * 3600
        self._stop = threading.Event()
        self._thread = None
        self.last_results = []

    def run_once(self):
        results = []
        for s in self.sources:
            try:
                res = s.fetch_if_updated(self.db)
            except Exception as e:  # jedan izvor ne smije srusiti ostale
                res = {"source": s.name, "status": "error",
                       "detail": "%s: %s" % (type(e).__name__, e)}
            log.info("[update] %s -> %s %s", res["source"], res["status"],
                     res.get("detail", ""))
            results.append(res)
        self.last_results = results
        return results

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self, timeout=5):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _loop(self):
        while not self._stop.is_set():
            try:
                results = self.run_once()
            except Exception:
                log.exception("[update] neocekivana greska")
                results = []
            all_failed = bool(results) and all(
                r["status"] == "error" for r in results)
            wait = min(300, self.interval_seconds) if all_failed \
                else self.interval_seconds
            if self._stop.wait(wait):
                break


# ---------------------------------------------------------------- arhiva

class LocalArchive:
    """Lokalna arhiva sumnjivih detekcija. NEMA slanja van.

    UPOZORENJE: sadrzi domene koje je korisnik kontaktirao = povijest
    pregledanja, u nesifrovanom SQLite fajlu. Zato postoji prune().
    """

    def __init__(self, db_path="redflag_local_archive.db"):
        self.db_path = db_path
        self.lock = threading.RLock()
        with self.lock, closing(sqlite3.connect(db_path)) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL,
                detection_type TEXT NOT NULL, evidence TEXT NOT NULL,
                detected_at TEXT NOT NULL)""")

    def add_detection(self, domain, detection_type, evidence):
        import json
        with self.lock, closing(sqlite3.connect(self.db_path)) as conn, conn:
            conn.execute(
                "INSERT INTO detections (domain, detection_type, evidence, "
                "detected_at) VALUES (?,?,?,?)",
                (domain, detection_type, json.dumps(evidence), utc_now()))

    def list_recent(self, limit=100):
        import json
        with self.lock, closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                "SELECT id, domain, detection_type, evidence, detected_at "
                "FROM detections ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"id": r[0], "domain": r[1], "detection_type": r[2],
                 "evidence": json.loads(r[3]), "detected_at": r[4]}
                for r in rows]

    def prune(self, max_age_days=90):
        cutoff = (datetime.now(timezone.utc) -
                  timedelta(days=max_age_days)).isoformat(timespec="seconds")
        with self.lock, closing(sqlite3.connect(self.db_path)) as conn, conn:
            return conn.execute(
                "DELETE FROM detections WHERE detected_at < ?",
                (cutoff,)).rowcount


# ---------------------------------------------------------------- heuristike

class PatternRecognition:
    """Heuristike nad VEC UHVACENIM zahtjevima. Ovaj paket ih ne hvata.

    Format zahtjeva: {"method": "POST", "url": "...", "body": "...",
                      "cookies": [{"name": "...", "max_age": sekunde}]}
    Rezultat 'no_signal' znaci samo "nijedna heuristika nije okinula",
    ne "domena je sigurna". Prag je NEKALIBRISAN (nema oznacenog skupa).
    """

    FINGERPRINT_KEYS = {"screen", "sr", "sw", "sh", "timezone", "tz",
                        "language", "lang", "platform", "canvas", "webgl",
                        "fonts", "colordepth", "cd", "plugins"}
    _B64 = re.compile(r"^[A-Za-z0-9+/_-]{64,}={0,2}$")

    def __init__(self, local_archive, min_signatures=3):
        self.archive = local_archive
        self.min_signatures = min_signatures
        self.signatures = {
            "large_post": self._large_post,
            "base64_in_url": self._base64_in_url,
            "long_cookie": self._long_cookie,
            "fingerprint_params": self._fingerprint_params,
        }

    def analyze_domain_behavior(self, domain, requests_list):
        hit = {}
        for req in requests_list:
            for name, check in self.signatures.items():
                if name not in hit and check(req):
                    hit[name] = True
        score = len(hit)
        if score >= self.min_signatures:
            flags = sorted(hit)
            self.archive.add_detection(
                domain, "behavioral_anomaly",
                {"score": score, "flags": flags,
                 "request_count": len(requests_list)})
            return {"status": "suspicious", "score": score, "flags": flags}
        return {"status": "no_signal", "score": score, "flags": sorted(hit)}

    @staticmethod
    def _large_post(req):
        return req.get("method") == "POST" and len(req.get("body") or "") > 10000

    @classmethod
    def _base64_in_url(cls, req):
        for _, v in parse_qsl(urlsplit(req.get("url", "")).query,
                              keep_blank_values=True):
            if cls._B64.match(v):
                try:
                    base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
                    return True
                except Exception:
                    pass
        return False

    @staticmethod
    def _long_cookie(req):
        return any((c.get("max_age") or 0) > 365 * 24 * 3600
                   for c in req.get("cookies") or [])

    @classmethod
    def _fingerprint_params(cls, req):
        keys = {k.lower() for k, _ in parse_qsl(
            urlsplit(req.get("url", "")).query, keep_blank_values=True)}
        return len(keys & cls.FINGERPRINT_KEYS) >= 3


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description="RedFlag Domain Intelligence")
    ap.add_argument("--db", default="redflag_domains.db")
    ap.add_argument("--sources", default="github",
                    choices=["github", "easylist_to", "all"])
    ap.add_argument("--once", action="store_true", help="jedno ažuriranje")
    ap.add_argument("--daemon", action="store_true", help="ažuriraj svaka 3h")
    ap.add_argument("--interval-hours", type=float, default=3.0)
    ap.add_argument("--force", action="store_true",
                    help="--once: prihvati i veliko smanjenje liste (ručna potvrda)")
    ap.add_argument("--check", nargs="+", metavar="DOMENA")
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    db = DomainDatabase(a.db)

    if a.once or a.daemon:
        if "NIJE-POSTAVLJENO" in USER_AGENT:
            sys.exit("PREKID: postavi REDFLAG_CONTACT=tvoj@email prije mrežnih zahtjeva.")
        sch = UpdateScheduler(db, build_sources(a.sources), a.interval_hours)
        if a.once:
            for src in sch.sources:
                print(src.fetch_if_updated(db, force=a.force))
        else:
            sch.start()
            try:
                threading.Event().wait()
            except KeyboardInterrupt:
                sch.stop()
    if a.check:
        for d in a.check:
            print(d, "->", db.check_domain(d))
    if a.stats:
        print(db.get_stats())


if __name__ == "__main__":
    main()
