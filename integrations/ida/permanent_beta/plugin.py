"""The IDA plugin: Edit > Plugins > Permanent Beta > Export markup / Apply markup from an older build (design §11.4).

It runs only `pbeta mappings` (a read) and writes only to the open database. It never decides a mapping or a
review item.
"""

from __future__ import annotations

import json
import os
import traceback

import ida_diskio
import ida_idaapi
import ida_kernwin
import ida_nalt

from . import core
from .ida_db import IdaDatabase

MENU_PARENT = "Edit/Plugins/"
MENU_NAME = "permanent_beta:menu"
MENU_LABEL = "Permanent Beta"
MENU = MENU_PARENT + MENU_LABEL + "/"
ACTION_EXPORT = "permanent_beta:export_markup"
ACTION_APPLY = "permanent_beta:apply_markup"


# --- settings (remembered between sessions, in IDA's user directory) ------------------------------------------


def _settings_path() -> str:
    return os.path.join(ida_diskio.get_user_idadir(), "permanent_beta.json")


def load_settings() -> dict:
    try:
        with open(_settings_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_settings(s: dict) -> None:
    try:
        with open(_settings_path(), "w", encoding="utf-8") as f:
            json.dump(s, f, indent=1)
    except OSError:
        pass


# --- export ----------------------------------------------------------------------------------------------------


def export_markup() -> None:
    db = IdaDatabase()
    markup = core.export_markup(db)
    default = os.path.splitext(ida_nalt.get_input_file_path() or "markup")[0] + ".pbeta-markup.json"
    path = ida_kernwin.ask_file(True, default, "Save the markup export")
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(markup.to_json())
    s = load_settings()
    s["markup"] = path
    save_settings(s)
    ida_kernwin.info(
        f"Exported markup for {len(markup.functions)} functions of build {markup.build[:12]}\nto {path}"
    )


# --- apply -----------------------------------------------------------------------------------------------------


class Settings(ida_kernwin.Form):
    def __init__(self, s: dict) -> None:
        super().__init__(
            r"""STARTITEM 0
BUTTON YES* Apply
BUTTON CANCEL Cancel
Apply markup from an older build

Carries names, prototypes, comments and types from the old build's markup export to this database,
across the function mappings pbeta accepted (by verification or a reviewer). Nothing else.

<pbeta executable          :{pbeta}>
<Markup export (old build) :{markup}>
<Old build's analysis      :{old}>
<This build's analysis     :{new}>
<Review store (optional)   :{store}>
""",
            {
                "pbeta": ida_kernwin.Form.FileInput(open=True, value=s.get("pbeta", "pbeta")),
                "markup": ida_kernwin.Form.FileInput(open=True, value=s.get("markup", "")),
                "old": ida_kernwin.Form.FileInput(open=True, value=s.get("old", "")),
                "new": ida_kernwin.Form.FileInput(open=True, value=s.get("new", "")),
                "store": ida_kernwin.Form.FileInput(open=True, value=s.get("store", "")),
            },
        )


def ask_settings():
    s = load_settings()
    form = Settings(s)
    form.Compile()
    try:
        if form.Execute() != 1:
            return None
        chosen = {k: getattr(form, k).value.strip() for k in ("pbeta", "markup", "old", "new", "store")}
    finally:
        form.Free()
    s.update(chosen)
    save_settings(s)
    return chosen


def apply_markup() -> None:
    chosen = ask_settings()
    if chosen is None:
        return
    for key in ("markup", "old", "new"):
        if not chosen[key]:
            raise core.PbetaError(f"choose the {key} file")
    with open(chosen["markup"], encoding="utf-8") as f:
        markup = core.MarkupExport.from_json(f.read())

    ida_kernwin.show_wait_box("Running pbeta mappings...")
    try:
        report = core.Pbeta(chosen["pbeta"]).mappings(
            chosen["old"], chosen["new"], chosen["store"] or None, chosen["markup"]
        )
    finally:
        ida_kernwin.hide_wait_box()

    db = IdaDatabase()
    core.check_builds(markup, report, db)
    question = (
        f"Carry markup for up to {len(report.mappings)} mapped functions into this database?\n"
        f"Names and prototypes you set here are kept."
    )
    if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, question) != ida_kernwin.ASKBTN_YES:
        return
    result = core.apply_markup(markup, report, db)
    global _results  # a non-modal chooser must outlive this call
    _results = ResultsChooser(db, result)
    _results.Show()
    ida_kernwin.info(core.summary(result))


_results = None


class ResultsChooser(ida_kernwin.Choose):
    """One row per carried, conflicting, skipped or pending function. Enter jumps to it."""

    def __init__(self, db: IdaDatabase, result: core.ApplyResult) -> None:
        super().__init__(
            "Permanent Beta: carried markup",
            [
                ["Address", 16 | ida_kernwin.Choose.CHCOL_HEX],
                ["Old RVA", 10 | ida_kernwin.Choose.CHCOL_HEX],
                ["Status", 10 | ida_kernwin.Choose.CHCOL_PLAIN],
                ["Detail", 70 | ida_kernwin.Choose.CHCOL_PLAIN],
            ],
            flags=ida_kernwin.Choose.CH_RESTORE,
        )
        self.rows = []
        self.eas = []
        for o in result.applied:
            ea = db.base + o.new
            for status, items in (("carried", o.applied), ("kept", o.conflicts), ("skipped", o.skipped)):
                for what in items:
                    self.rows.append([hex(ea), hex(o.old), status, what])
                    self.eas.append(ea)
        for o in result.pending:
            self.rows.append(["", hex(o.old), "pending", o.skipped[0]])
            self.eas.append(None)

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return self.rows[n]

    def OnSelectLine(self, n):
        ea = self.eas[n]
        if ea is not None:
            ida_kernwin.jumpto(ea)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)


# --- registration ----------------------------------------------------------------------------------------------


class _Handler(ida_kernwin.action_handler_t):
    def __init__(self, fn) -> None:
        super().__init__()
        self.fn = fn

    def activate(self, ctx):
        try:
            self.fn()
        except core.PbetaError as e:
            ida_kernwin.warning(f"Permanent Beta: {e}")
        except Exception:  # noqa: BLE001 - show anything else rather than lose it in IDA's output
            ida_kernwin.warning("Permanent Beta failed:\n" + traceback.format_exc())
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = (
    (ACTION_EXPORT, "Export markup...", export_markup),
    (ACTION_APPLY, "Apply markup from an older build...", apply_markup),
)


def attach_menu() -> bool:
    """(Re)build Edit > Plugins > Permanent Beta. A submenu has to be created before actions can go in it."""
    for name, _, _ in ACTIONS:
        ida_kernwin.detach_action_from_menu(MENU, name)
    ida_kernwin.delete_menu(MENU_NAME)
    ok = ida_kernwin.create_menu(MENU_NAME, MENU_LABEL, MENU_PARENT)
    for name, _, _ in ACTIONS:
        ok = ida_kernwin.attach_action_to_menu(MENU, name, ida_kernwin.SETMENU_APP) and ok
    return bool(ok)


class _UiHooks(ida_kernwin.UI_Hooks):
    """IDA fills Edit > Plugins as plugins load; attach again once the UI is ready, so the submenu survives."""

    def ready_to_run(self):
        ok = attach_menu()
        ida_kernwin.msg(f"Permanent Beta: {'added' if ok else 'could not add'} {MENU.rstrip('/')}\n")


class PermanentBetaPlugin(ida_idaapi.plugin_t):
    # Loaded with each database. PLUGIN_HIDE: no one-click Edit > Plugins entry of IDA's own; the actions have
    # their own submenu there (MENU). PLUGIN_KEEP is init's return value, not a flag.
    flags = ida_idaapi.PLUGIN_HIDE
    comment = "Carry markup to a new build across verified function mappings"
    help = "Edit > Plugins > Permanent Beta"
    wanted_name = "Permanent Beta"
    wanted_hotkey = ""

    def init(self):
        for name, label, fn in ACTIONS:
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, _Handler(fn)))
        ok = attach_menu()
        ida_kernwin.msg(f"Permanent Beta: {'added' if ok else 'will add'} {MENU.rstrip('/')}\n")
        self.hooks = _UiHooks()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        apply_markup_safely()

    def term(self):
        self.hooks.unhook()
        for name, _, _ in ACTIONS:
            ida_kernwin.detach_action_from_menu(MENU, name)
            ida_kernwin.unregister_action(name)
        ida_kernwin.delete_menu(MENU_NAME)


def apply_markup_safely():
    _Handler(apply_markup).activate(None)
