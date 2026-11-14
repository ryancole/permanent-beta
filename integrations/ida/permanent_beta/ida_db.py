"""`core.Database` over the open IDA database (IDA 9.x, IDAPython). Addresses are image base + RVA."""

from __future__ import annotations

from typing import Optional

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_name
import ida_typeinf
import idautils
import idc


class IdaDatabase:
    def __init__(self) -> None:
        self.base = ida_nalt.get_imagebase()

    def _ea(self, rva: int) -> int:
        return self.base + rva

    def _func(self, rva: int):
        f = ida_funcs.get_func(self._ea(rva))
        return f if f is not None and f.start_ea == self._ea(rva) else None

    def sha256(self) -> Optional[str]:
        digest = ida_nalt.retrieve_input_file_sha256()
        return digest.hex() if digest else None

    def function_rvas(self) -> list[int]:
        return [ea - self.base for ea in idautils.Functions()]

    def has_function(self, rva: int) -> bool:
        return self._func(rva) is not None

    def is_library(self, rva: int) -> bool:
        f = self._func(rva)
        return bool(f and f.flags & (ida_funcs.FUNC_LIB | ida_funcs.FUNC_THUNK))

    def user_name(self, rva: int) -> Optional[str]:
        ea = self._ea(rva)
        if not ida_bytes.has_user_name(ida_bytes.get_flags(ea)):
            return None
        return ida_name.get_name(ea) or None

    def name_owner(self, name: str) -> Optional[int]:
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
        return None if ea == ida_idaapi.BADADDR else ea - self.base

    def set_name(self, rva: int, name: str) -> bool:
        return bool(ida_name.set_name(self._ea(rva), name, ida_name.SN_NOWARN))

    def user_prototype(self, rva: int) -> Optional[str]:
        ea = self._ea(rva)
        is_user = getattr(ida_nalt, "is_userti", None)
        if is_user is not None and not is_user(ea):
            return None
        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, ea) or not tif.is_func():
            return None
        name = ida_name.get_name(ea)
        text = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, "")
        return text or None

    def set_prototype(self, rva: int, prototype: str) -> bool:
        decl = prototype.strip()
        if not decl.endswith(";"):
            decl += ";"
        return bool(idc.SetType(self._ea(rva), decl))

    def comment(self, rva: int, repeatable: bool) -> str:
        f = self._func(rva)
        return (ida_funcs.get_func_cmt(f, repeatable) or "") if f else ""

    def set_comment(self, rva: int, text: str, repeatable: bool) -> bool:
        f = self._func(rva)
        return bool(f and ida_funcs.set_func_cmt(f, text, repeatable))

    def local_types(self) -> str:
        limit = (
            ida_typeinf.get_ordinal_limit()
            if hasattr(ida_typeinf, "get_ordinal_limit")
            else ida_typeinf.get_ordinal_qty(None) + 1
        )
        if limit <= 1:
            return ""
        ordinals = ",".join(str(i) for i in range(1, limit))
        return idc.print_decls(ordinals, idc.PDF_INCL_DEPS | idc.PDF_DEF_FWD) or ""

    def import_types(self, text: str) -> int:
        errors = idc.parse_decls(text, idc.PT_SILENT)
        return max(errors, 0) if isinstance(errors, int) else 0
