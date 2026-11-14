"""Markup carry-forward without IDA (design §11.4): the export format, the apply rules and the pbeta client.

Everything that touches a database goes through the `Database` interface (`ida_db.IdaDatabase` in IDA, a fake in
the tests), so these rules are tested without IDA. Nothing here decides a mapping: which functions correspond is
`pbeta mappings`' answer, used as it is.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

FORMAT = "pbeta-markup"
VERSION = 1

# Names IDA generates for functions; never carried (the new database generates its own).
GENERATED_PREFIXES = ("sub_", "nullsub_", "j_", "unknown_libname_", "loc_", "locret_")

PROVENANCE_TAG = "pbeta:"


class PbetaError(Exception):
    """A refusal or failure, with a message meant for the user."""


# --- the export format ---------------------------------------------------------------------------------------


@dataclass
class FunctionMarkup:
    rva: int
    name: Optional[str] = None
    prototype: Optional[str] = None
    comment: Optional[str] = None
    repeatable_comment: Optional[str] = None

    def to_json(self) -> dict:
        out: dict = {"rva": hex(self.rva)}
        for key in ("name", "prototype", "comment", "repeatable_comment"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out

    @staticmethod
    def from_json(d: dict) -> "FunctionMarkup":
        return FunctionMarkup(
            rva=parse_rva(d["rva"]),
            name=d.get("name"),
            prototype=d.get("prototype"),
            comment=d.get("comment"),
            repeatable_comment=d.get("repeatable_comment"),
        )


@dataclass
class MarkupExport:
    build: str
    functions: list[FunctionMarkup]
    types: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "format": FORMAT,
                "version": VERSION,
                "build": self.build,
                "functions": [f.to_json() for f in sorted(self.functions, key=lambda f: f.rva)],
                "types": self.types,
            },
            indent=1,
        )

    @staticmethod
    def from_json(text: str) -> "MarkupExport":
        d = json.loads(text)
        if d.get("format") != FORMAT or d.get("version") != VERSION:
            raise PbetaError(
                f"not a {FORMAT} v{VERSION} export (format {d.get('format')!r}, version {d.get('version')!r})"
            )
        return MarkupExport(
            build=d["build"].lower(),
            functions=[FunctionMarkup.from_json(f) for f in d["functions"]],
            types=d.get("types", ""),
        )


def parse_rva(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text)


def is_generated_name(name: Optional[str]) -> bool:
    return not name or name.startswith(GENERATED_PREFIXES)


# --- the database interface ----------------------------------------------------------------------------------


class Database(Protocol):
    """One open database, addressed by RVA. `IdaDatabase` implements it in IDA."""

    def sha256(self) -> Optional[str]: ...

    def function_rvas(self) -> list[int]: ...

    def has_function(self, rva: int) -> bool: ...

    def is_library(self, rva: int) -> bool:
        """IDA recognised the function itself (a library or thunk function): its name isn't the user's work."""

    def user_name(self, rva: int) -> Optional[str]:
        """The function's name if a user set it, else None."""

    def name_owner(self, name: str) -> Optional[int]:
        """The RVA that has this name, if any."""

    def set_name(self, rva: int, name: str) -> bool: ...

    def user_prototype(self, rva: int) -> Optional[str]:
        """The function's prototype, named, if a user set one, else None."""

    def set_prototype(self, rva: int, prototype: str) -> bool: ...

    def comment(self, rva: int, repeatable: bool) -> str: ...

    def set_comment(self, rva: int, text: str, repeatable: bool) -> bool: ...

    def local_types(self) -> str:
        """The database's local types as C declarations."""

    def import_types(self, text: str) -> int:
        """Parse C declarations into the local types; returns the number of errors."""


# --- export --------------------------------------------------------------------------------------------------


def export_markup(db: Database) -> MarkupExport:
    """The user's markup per function: names the user set, prototypes the user set, function comments. Library and
    thunk functions IDA recognised itself are left out (the new build's database recognises them too), and so are
    carried provenance lines, so markup carried twice doesn't stack them."""
    build = db.sha256()
    if not build:
        raise PbetaError("this database has no input file SHA-256, so it can't be tied to a build")
    functions = []
    for rva in db.function_rvas():
        if db.is_library(rva):
            continue
        name = db.user_name(rva)
        f = FunctionMarkup(
            rva=rva,
            name=None if is_generated_name(name) else name,
            prototype=db.user_prototype(rva),
            comment=strip_provenance(db.comment(rva, False)) or None,
            repeatable_comment=db.comment(rva, True) or None,
        )
        if f.name or f.prototype or f.comment or f.repeatable_comment:
            functions.append(f)
    return MarkupExport(build=build.lower(), functions=functions, types=db.local_types())


def strip_provenance(comment: str) -> str:
    lines = [line for line in (comment or "").splitlines() if not line.startswith(PROVENANCE_TAG)]
    return "\n".join(lines).strip()


# --- pbeta mappings ------------------------------------------------------------------------------------------


@dataclass
class Mapping:
    old: int
    new: int
    decided_by: str  # "engine" or "reviewer <name>"


@dataclass
class MappingsReport:
    from_build: str
    to_build: str
    mappings: list[Mapping]
    pending: dict[int, str]  # old RVA -> reason
    prototype_misfits: dict[int, str]  # old RVA -> detail

    @staticmethod
    def from_json(text: str) -> "MappingsReport":
        d = json.loads(text)

        def decider(m: dict) -> str:
            by = m["decided_by"]
            return "engine" if by.get("kind") == "engine" else f"reviewer {by.get('reviewer', '?')}"

        return MappingsReport(
            from_build=d["from_build"].lower(),
            to_build=d["to_build"].lower(),
            mappings=[
                Mapping(parse_rva(m["old"]), parse_rva(m["new"]), decider(m))
                for m in d["mappings"]
                if m.get("status", "accepted") == "accepted"
            ],
            pending={parse_rva(p["old"]): p["reason"] for p in d.get("pending", [])},
            prototype_misfits={parse_rva(p["old"]): p["detail"] for p in d.get("prototype_misfits", [])},
        )


Runner = Callable[[list[str]], "tuple[int, str, str]"]


def run_process(args: list[str]) -> "tuple[int, str, str]":
    # CREATE_NO_WINDOW on Windows: no console flashes up from inside IDA.
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", creationflags=flags)
    return p.returncode, p.stdout, p.stderr


@dataclass
class Pbeta:
    """Runs the pbeta CLI. Only `pbeta mappings`, which reads; the plugin writes no mapping."""

    program: str
    runner: Runner = field(default=run_process)

    def mappings(
        self, old_analysis: str, new_analysis: str, store: Optional[str], markup: Optional[str]
    ) -> MappingsReport:
        args = [self.program, "mappings", "--old", old_analysis, "--new", new_analysis, "--json"]
        if store:
            args += ["--store", store]
        if markup:
            args += ["--markup", markup]
        try:
            code, out, err = self.runner(args)
        except FileNotFoundError:
            raise PbetaError(
                f"can't find pbeta at {self.program!r}: give the full path to pbeta.exe "
                f"(for a source checkout, target\\debug\\pbeta.exe after cargo build)"
            ) from None
        if code != 0:
            raise PbetaError(f"pbeta mappings failed (exit {code}): {err.strip() or out.strip()}")
        return MappingsReport.from_json(out)


# --- apply ---------------------------------------------------------------------------------------------------


@dataclass
class Outcome:
    old: int
    new: Optional[int]
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # "what: why"
    conflicts: list[str] = field(default_factory=list)  # "what: why"


@dataclass
class ApplyResult:
    applied: list[Outcome]
    pending: list[Outcome]
    type_errors: int

    def conflicts(self) -> list[Outcome]:
        return [o for o in self.applied if o.conflicts]

    def skipped(self) -> list[Outcome]:
        return [o for o in self.applied if o.skipped]


def provenance(report: MappingsReport, m: Mapping) -> str:
    return f"{PROVENANCE_TAG} carried from build {report.from_build[:12]} {hex(m.old)}, mapped by {m.decided_by}"


def check_builds(markup: MarkupExport, report: MappingsReport, db: Database) -> None:
    """Refuse unless the markup is the old build's and this database is the new build's."""
    if markup.build != report.from_build:
        raise PbetaError(
            f"the markup was exported from build {markup.build[:12]}, but the old analysis is build "
            f"{report.from_build[:12]}"
        )
    here = (db.sha256() or "").lower()
    if here != report.to_build:
        raise PbetaError(
            f"this database is build {here[:12] or '(no SHA-256)'}, but the new analysis is build "
            f"{report.to_build[:12]}: open the new build's database"
        )


def apply_markup(markup: MarkupExport, report: MappingsReport, db: Database) -> ApplyResult:
    """Carry `markup` (the old build's) to `db` (the new build's) across the report's accepted mappings only.

    Rules (design §11.4): nothing for a pending function; a name or prototype the user already set here is kept and
    listed as a conflict; a prototype `pbeta` found doesn't fit the new function isn't applied; a name another
    function here has is skipped; every function that got markup gets a provenance line. Applying twice changes
    nothing the second time.
    """
    check_builds(markup, report, db)
    by_old = {f.rva: f for f in markup.functions}
    type_errors = db.import_types(markup.types) if markup.types.strip() else 0

    applied: list[Outcome] = []
    for m in report.mappings:
        f = by_old.get(m.old)
        if f is None:
            continue
        o = Outcome(old=m.old, new=m.new)
        applied.append(o)
        if not db.has_function(m.new):
            o.skipped.append(f"everything: IDA has no function starting at {hex(m.new)}")
            continue
        _apply_name(f, m, db, o)
        _apply_prototype(f, m, report, db, o)
        _apply_repeatable(f, m, db, o)
        _apply_comment(f, m, report, db, o)  # last: it adds the provenance line if anything was carried

    mapped = {m.old for m in report.mappings}
    pending = [
        Outcome(old=f.rva, new=None, skipped=[f"everything: {report.pending.get(f.rva, 'not in the old analysis')}"])
        for f in markup.functions
        if f.rva not in mapped
    ]
    return ApplyResult(applied=applied, pending=pending, type_errors=type_errors)


def _apply_name(f: FunctionMarkup, m: Mapping, db: Database, o: Outcome) -> None:
    if is_generated_name(f.name):
        return
    here = db.user_name(m.new)
    if here == f.name:
        return
    if here and not is_generated_name(here):
        o.conflicts.append(f"name: kept {here!r}, not {f.name!r}")
        return
    owner = db.name_owner(f.name)
    if owner is not None and owner != m.new:
        o.skipped.append(f"name: {f.name!r} is already used at {hex(owner)}")
        return
    if db.set_name(m.new, f.name):
        o.applied.append("name")
    else:
        o.skipped.append(f"name: IDA refused {f.name!r}")


def _apply_prototype(f: FunctionMarkup, m: Mapping, report: MappingsReport, db: Database, o: Outcome) -> None:
    if not f.prototype:
        return
    misfit = report.prototype_misfits.get(m.old)
    if misfit:
        o.skipped.append(f"prototype: doesn't fit the new function ({misfit})")
        return
    here = db.user_prototype(m.new)
    if here and _same_prototype(here, f.prototype):
        return
    if here:
        o.conflicts.append(f"prototype: kept {here!r}")
        return
    if db.set_prototype(m.new, f.prototype):
        o.applied.append("prototype")
    else:
        o.skipped.append(f"prototype: IDA couldn't parse {f.prototype!r}")


def _same_prototype(a: str, b: str) -> bool:
    return " ".join(a.replace(";", "").split()) == " ".join(b.replace(";", "").split())


def _apply_comment(f: FunctionMarkup, m: Mapping, report: MappingsReport, db: Database, o: Outcome) -> None:
    here = db.comment(m.new, False) or ""
    carried = strip_provenance(f.comment or "")
    want = []
    if carried and carried not in here:
        if strip_provenance(here):
            o.conflicts.append("comment: kept the existing comment")
        else:
            want.append(carried)
    has_tag = any(line.startswith(PROVENANCE_TAG) for line in here.splitlines())
    if (want or o.applied) and not has_tag:
        want.append(provenance(report, m))
    if not want:
        return
    text = "\n".join(([here.rstrip()] if here.strip() else []) + want)
    if not db.set_comment(m.new, text, False):
        o.skipped.append("comment: IDA refused it")
    elif carried in want:
        o.applied.append("comment")


def _apply_repeatable(f: FunctionMarkup, m: Mapping, db: Database, o: Outcome) -> None:
    if not f.repeatable_comment:
        return
    here = db.comment(m.new, True) or ""
    if f.repeatable_comment in here:
        return
    if here.strip():
        o.conflicts.append("repeatable comment: kept the existing one")
        return
    if db.set_comment(m.new, f.repeatable_comment, True):
        o.applied.append("repeatable comment")
    else:
        o.skipped.append("repeatable comment: IDA refused it")


def summary(result: ApplyResult) -> str:
    got = sum(1 for o in result.applied if o.applied)
    lines = [
        f"{got} functions got markup; {len(result.conflicts())} kept their own; "
        f"{len(result.skipped())} had something skipped; {len(result.pending)} not carried (no accepted mapping)."
    ]
    if result.type_errors:
        lines.append(f"{result.type_errors} type declarations didn't parse.")
    return "\n".join(lines)
