"""Tests for the plugin's IDA-free logic. Run from integrations/ida: python -m unittest discover -s tests

Data (tests/data, see README.md there): a markup export of the hook loop's /O2 v2 build (names from its map file,
prototypes from corpus/hooks/hooks.template.toml), and the real `pbeta mappings --markup` reply for v2 -> v3.
"""

from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from permanent_beta import core  # noqa: E402
from permanent_beta.core import FunctionMarkup, MarkupExport, MappingsReport, PbetaError  # noqa: E402


def data(name: str) -> str:
    with open(os.path.join(HERE, "data", name), encoding="utf-8") as f:
        return f.read()


class FakeDatabase:
    """An in-memory database: what the IDA adapter reads and writes, by RVA."""

    def __init__(self, sha256, functions, names=None, prototypes=None, comments=None):
        self._sha = sha256
        self.functions = set(functions)
        self.names = dict(names or {})
        self.prototypes = dict(prototypes or {})
        self.comments = dict(comments or {})  # (rva, repeatable) -> text
        self.types = ""
        self.writes = 0
        self.library = set()

    def is_library(self, rva):
        return rva in self.library

    def sha256(self):
        return self._sha

    def function_rvas(self):
        return sorted(self.functions)

    def has_function(self, rva):
        return rva in self.functions

    def user_name(self, rva):
        return self.names.get(rva)

    def name_owner(self, name):
        return next((r for r, n in self.names.items() if n == name), None)

    def set_name(self, rva, name):
        self.writes += 1
        self.names[rva] = name
        return True

    def user_prototype(self, rva):
        return self.prototypes.get(rva)

    def set_prototype(self, rva, prototype):
        self.writes += 1
        self.prototypes[rva] = prototype
        return True

    def comment(self, rva, repeatable):
        return self.comments.get((rva, repeatable), "")

    def set_comment(self, rva, text, repeatable):
        self.writes += 1
        self.comments[(rva, repeatable)] = text
        return True

    def local_types(self):
        return self.types

    def import_types(self, text):
        self.types += text
        return 0


def recorded():
    return MarkupExport.from_json(data("markup-o2-v2.json")), MappingsReport.from_json(data("mappings-o2-v2-v3.json"))


def v3_database(report: MappingsReport, **kw) -> FakeDatabase:
    rvas = {m.new for m in report.mappings} | {0x1380}
    return FakeDatabase(report.to_build, rvas, **kw)


class ExportTest(unittest.TestCase):
    def test_exports_user_markup_only(self):
        db = FakeDatabase(
            "ABCD",
            [0x10, 0x20, 0x30, 0x40],
            names={0x10: "parse", 0x20: "sub_140001020", 0x40: "j_parse"},
            prototypes={0x10: "int __fastcall parse(Packet *p)"},
            comments={(0x30, False): "pbeta: carried from build x 0x1, mapped by engine\nreal note"},
        )
        db.types = "struct Packet { int len; };"
        db.functions.add(0x50)
        db.names[0x50] = "memcpy"
        db.prototypes[0x50] = "void *__cdecl memcpy(void *, const void *Src, size_t Size)"
        db.library.add(0x50)
        m = MarkupExport.from_json(core.export_markup(db).to_json())
        self.assertEqual(m.build, "abcd")
        by = {f.rva: f for f in m.functions}
        self.assertEqual(by[0x10].name, "parse")
        self.assertEqual(by[0x10].prototype, "int __fastcall parse(Packet *p)")
        # Negative: IDA's generated names aren't exported, and neither is a function with nothing else.
        self.assertNotIn(0x20, by)
        self.assertNotIn(0x40, by)
        # Negative: a library function IDA recognised (FLIRT, import thunks) isn't the user's work.
        self.assertNotIn(0x50, by)
        # Negative: a carried provenance line isn't exported again.
        self.assertEqual(by[0x30].comment, "real note")
        self.assertIn("Packet", m.types)

    def test_a_database_without_a_hash_is_refused(self):
        with self.assertRaises(PbetaError):
            core.export_markup(FakeDatabase(None, [0x10], names={0x10: "f"}))

    def test_another_format_is_refused(self):
        with self.assertRaises(PbetaError):
            MarkupExport.from_json(json.dumps({"format": "other", "version": 1, "build": "a", "functions": []}))


class ApplyTest(unittest.TestCase):
    def test_carries_markup_across_accepted_mappings(self):
        markup, report = recorded()
        db = v3_database(report)
        r = core.apply_markup(markup, report, db)
        # The map files: v2 price_lookup 0x12b0 is v3 0x12f0, format_receipt 0x1070 -> 0x10a0.
        self.assertEqual(db.names[0x12F0], "price_lookup")
        self.assertEqual(db.names[0x10A0], "format_receipt")
        self.assertEqual(db.prototypes[0x12F0], "int price_lookup(int sku)")
        self.assertIn("looks up the price table", db.comments[(0x12F0, False)])
        self.assertIn("pbeta: carried from build 02c38963d4cb 0x12b0", db.comments[(0x12F0, False)])
        self.assertEqual(db.comments[(0x14F0, True)], "stock in units")
        self.assertIn("Order", db.types)
        self.assertEqual(r.type_errors, 0)

    def test_nothing_for_a_function_without_an_accepted_mapping(self):
        # Negative: checksum (0x1040) is ambiguous, ship_order (0x1340) needs review with candidate 0x1380.
        markup, report = recorded()
        db = v3_database(report)
        r = core.apply_markup(markup, report, db)
        self.assertNotIn("checksum", db.names.values())
        self.assertNotIn("ship_order", db.names.values())
        self.assertNotIn(0x1380, db.names)
        self.assertNotIn(0x1380, db.prototypes)
        pending = {o.old: o.skipped[0] for o in r.pending}
        self.assertIn("ambiguous", pending[0x1040])
        self.assertIn("needs_review", pending[0x1340])

    def test_the_users_own_name_and_prototype_are_kept(self):
        markup, report = recorded()
        db = v3_database(report, names={0x12F0: "get_price"}, prototypes={0x12F0: "int get_price(int id)"})
        r = core.apply_markup(markup, report, db)
        # Negative: nothing the user set here is overwritten.
        self.assertEqual(db.names[0x12F0], "get_price")
        self.assertEqual(db.prototypes[0x12F0], "int get_price(int id)")
        o = next(o for o in r.applied if o.new == 0x12F0)
        self.assertEqual(len(o.conflicts), 2, o.conflicts)
        self.assertIn("comment", o.applied)

    def test_a_misfitting_prototype_is_not_applied(self):
        markup, report = recorded()
        # Hand-written: pbeta lists a misfit (its own check is tested in the engine with real features).
        report.prototype_misfits[0x12B0] = "it reads rdx (argument 2), which the prototype doesn't declare"
        db = v3_database(report)
        r = core.apply_markup(markup, report, db)
        self.assertNotIn(0x12F0, db.prototypes)
        self.assertEqual(db.names[0x12F0], "price_lookup", "the name still goes across")
        o = next(o for o in r.applied if o.new == 0x12F0)
        self.assertTrue(any("doesn't fit" in s for s in o.skipped), o.skipped)

    def test_a_name_used_elsewhere_is_skipped(self):
        markup, report = recorded()
        db = v3_database(report, names={0x2000: "price_lookup"})
        r = core.apply_markup(markup, report, db)
        # Negative: IDA names are unique; the other function keeps it.
        self.assertNotIn(0x12F0, db.names)
        o = next(o for o in r.applied if o.new == 0x12F0)
        self.assertTrue(any("already used at 0x2000" in s for s in o.skipped), o.skipped)

    def test_a_generated_name_here_is_replaced(self):
        markup, report = recorded()
        db = v3_database(report, names={0x12F0: "sub_1400012F0"})
        core.apply_markup(markup, report, db)
        self.assertEqual(db.names[0x12F0], "price_lookup")

    def test_applying_twice_changes_nothing(self):
        markup, report = recorded()
        db = v3_database(report)
        core.apply_markup(markup, report, db)
        before = (dict(db.names), dict(db.prototypes), dict(db.comments))
        writes = db.writes
        r = core.apply_markup(markup, report, db)
        self.assertEqual((db.names, db.prototypes, db.comments), before)
        self.assertEqual(db.writes, writes)
        self.assertFalse(any(o.applied for o in r.applied))

    def test_another_builds_database_is_refused(self):
        markup, report = recorded()
        # Negative: the old build's own database, and a database without a hash.
        for sha in (report.from_build, None):
            db = FakeDatabase(sha, [m.new for m in report.mappings])
            with self.assertRaises(PbetaError):
                core.apply_markup(markup, report, db)
            self.assertEqual(db.names, {})

    def test_markup_from_another_build_is_refused(self):
        markup, report = recorded()
        markup.build = "ffff"
        db = v3_database(report)
        with self.assertRaises(PbetaError):
            core.apply_markup(markup, report, db)
        self.assertEqual(db.writes, 0)

    def test_a_function_ida_does_not_have_is_skipped(self):
        markup, report = recorded()
        db = v3_database(report)
        db.functions.discard(0x12F0)
        r = core.apply_markup(markup, report, db)
        self.assertNotIn(0x12F0, db.names)
        o = next(o for o in r.applied if o.new == 0x12F0)
        self.assertIn("no function starting at 0x12f0", o.skipped[0])


class PbetaClientTest(unittest.TestCase):
    def test_runs_pbeta_mappings_and_parses_the_reply(self):
        calls = []

        def runner(args):
            calls.append(args)
            return 0, data("mappings-o2-v2-v3.json"), ""

        r = core.Pbeta("pbeta", runner).mappings("old.json", "new.json", "store.json", "markup.json")
        self.assertEqual(
            calls[0],
            ["pbeta", "mappings", "--old", "old.json", "--new", "new.json", "--json",
             "--store", "store.json", "--markup", "markup.json"],
        )
        self.assertEqual(len(r.mappings), 67)
        self.assertEqual(r.mappings[0].decided_by, "engine")
        self.assertEqual(r.pending[0x1040], "ambiguous")

    def test_a_failure_carries_pbetas_message(self):
        runner = lambda args: (2, "", "error: the markup was exported from build 02c3, not the old build c53f\n")  # noqa: E731
        with self.assertRaises(PbetaError) as e:
            core.Pbeta("pbeta", runner).mappings("o", "n", None, "m")
        self.assertIn("not the old build", str(e.exception))

    def test_a_missing_pbeta_says_where_it_looked(self):
        def runner(args):
            raise FileNotFoundError(2, "The system cannot find the file specified")

        with self.assertRaises(PbetaError) as e:
            core.Pbeta("pbeta", runner).mappings("o", "n", None, None)
        self.assertIn("can't find pbeta at 'pbeta'", str(e.exception))

    def test_reviewer_decisions_are_named(self):
        reply = json.dumps({
            "from_build": "a", "to_build": "b", "pending": [],
            "mappings": [
                {"old": "0x10", "new": "0x20", "decided_by": {"kind": "human", "reviewer": "ryan"}, "status": "accepted"},
                # Negative: anything but a live mapping is ignored.
                {"old": "0x30", "new": "0x40", "decided_by": {"kind": "engine"}, "status": "revoked"},
            ],
        })
        r = MappingsReport.from_json(reply)
        self.assertEqual([(m.old, m.new, m.decided_by) for m in r.mappings], [(0x10, 0x20, "reviewer ryan")])


class ManifestTest(unittest.TestCase):
    """ida-plugin.json: what IDA and Hex-Rays' plugin manager (HCLI) require of it."""

    def test_has_the_required_fields_and_its_entry_point(self):
        with open(os.path.join(os.path.dirname(HERE), "ida-plugin.json"), encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual(m["IDAMetadataDescriptorVersion"], 1)
        p = m["plugin"]
        for key in ("name", "version", "entryPoint", "urls"):
            self.assertIn(key, p)
        self.assertTrue(p["urls"].get("repository"))
        self.assertTrue(any(a.get("email") for a in p.get("authors", []) + p.get("maintainers", [])))
        self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(HERE), p["entryPoint"])))


if __name__ == "__main__":
    unittest.main()
