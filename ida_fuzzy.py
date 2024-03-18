# homepage: https://github.com/Ga-ryo/IDAFuzzy

# pylint: disable=C0103,C0111,C0301

from __future__ import print_function

import gc
import functools
import threading
from thefuzz import process, fuzz

import idc
import idaapi
import idautils

from idaapi import Form
from idaapi import Choose
from PyQt5 import QtCore

"""
Fuzzy Search v1.0
Goal
1. Search and execute IDA Pro's feature by name(ex: file,next code, run, attach to process ... )
2. Search and goto Function, string, struct,...
3. Automatically update. (when user rename function, hook and refresh)

Choose.CH_QFTYP_FUZZY is not so usable.
1. Not so fuzzy.
2. In the first place, fuzzy choose isn't applied to Functions Window or other embedded chooser.

@TODO
1. Installation
 - install idapython
 - pip install fuzzywuzzy
 - put this file to plugins directory.

2. Usage
3. Implement
 - All feature
 - Functions (hook rename and reload automatically)
 - Strings (symbol and Contents)
 - Structures
 - etc...

4. Show hint?
 - Name = "strings windows", Hint = "Open strings subview in current context."
  -- but add column affects number of pushing tab.
"""

LISTLEN = 10


class Commands:
    """
    Command execution proxy.
    """

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        assert callable(kwargs["fptr"])

    @property
    def description(self):
        return self.kwargs.get("description")

    def execute(self):
        if self.kwargs.get("args") is not None:
            self.kwargs.get("fptr")(*self.kwargs.get("args"))
        else:
            self.kwargs.get("fptr")()

    def get_icon(self):
        if self.kwargs.get("icon") is None:
            return 0
        return self.kwargs.get("icon")


choices: dict = {}
names: list = []


class EmbeddedChooserClass(Choose):
    """
    A simple chooser to be used as an embedded chooser
    """

    def __init__(self, form, title, flags=0):
        super().__init__(title, [["Action/Name", 30 | Choose.CHCOL_PLAIN]], embedded=True, height=20, flags=flags)
        self.form = form
        self.items = []
        self.icon = 0

    def OnGetIcon(self, n):
        if 0 <= n < len(self.items):
            return choices[self.items[n][0]].get_icon()
        return -1

    def OnSelectLine(self, sel):
        if 0 <= sel < len(self.items):
            self.form.Close(1)

    def OnGetLine(self, n):
        if 0 <= n < len(self.items):
            return self.items[n]
        return [""]

    def OnGetSize(self):
        return len(self.items)


class TerminateException(Exception):
    pass


def hooked_scorer(*args, **kwargs):
    if kwargs.pop("terminate_event").is_set():
        raise TerminateException
    return fuzz.WRatio(*args, **kwargs)


class FuzzySearchThread(QtCore.QThread):
    refresh_list = QtCore.pyqtSignal([str] * LISTLEN)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stopped = False
        self.mutex = QtCore.QMutex()
        self.terminate_event = threading.Event()

    def setup(self, s):
        self.stopped = False
        self.s = s

    def stop(self):
        with QtCore.QMutexLocker(self.mutex):
            self.stopped = True

    def run(self):
        f = functools.partial(hooked_scorer, terminate_event=self.terminate_event)
        try:
            res = process.extract(
                self.s, names, limit=LISTLEN, scorer=f
            )  # f.iStr1.value won't change until Form.Execute() returns.
            extracts = []
            for i in res:
                extracts.append(i[0])
            for i in range(10 - len(res)):
                extracts.append("")
            self.refresh_list.emit(*extracts)  # call main Thread's UI function.
        except TerminateException:
            pass
        self.stop()
        self.finished.emit()


class FuzzySearchForm(Form):
    def __init__(self):
        self.invert = False
        self.EChooser = EmbeddedChooserClass(self, "", flags=Choose.CH_MODAL)
        self.ctrlChooser = None
        self.iStr1 = None
        self.selected_id = 0
        self.s = ""
        self.fst = FuzzySearchThread()
        self.fst.refresh_list.connect(self.refresh_list)
        self.fst.finished.connect(self.finished)

        Form.__init__(
            self,
            r"""STARTITEM {id:iStr1}
IDA Fuzzy Search
{FormChangeCb}
<:{iStr1}>

<Results:{ctrlChooser}>
""",
            {
                "iStr1": Form.StringInput(),
                "ctrlChooser": Form.EmbeddedChooserControl(self.EChooser),
                "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
            },
        )

    def OnFormChange(self, fid):
        if fid == -1:
            # initialize
            pass
        elif fid == -2:
            # terminate
            pass
        elif fid == self.ctrlChooser.id:
            value = self.GetControlValue(self.ctrlChooser)
            if value:
                self.selected_id = value[0]
        elif fid == self.iStr1.id:
            self.s = self.GetControlValue(self.iStr1)
            self.EChooser.items = []
            if self.s == "":
                self.RefreshField(self.ctrlChooser)
                return 1
            self.fst.stop()
            self.fst.quit()  # if you type speedy, FuzzySearch which executed before is not finished here.
            self.fst.terminate_event.set()
            self.fst.wait()
            # self.fst.terminate()   # but last time's FuzzySearch is meaningless, so terminate this. <- little dangerous?

            # stop and quit take time.(and maybe non-blocking)
            # So if you type speedy, some start() call will be ignored.
            # re-create thread solve this.
            self.fst = FuzzySearchThread()
            self.fst.refresh_list.connect(self.refresh_list)
            self.fst.finished.connect(self.finished)
            self.fst.setup(self.s)
            self.fst.start()

            # extracts = process.extract(s, names, limit=10)  # f.iStr1.value won't change until Form.Execute() returns.
        else:
            pass
        return 1

    def refresh_list(self, *extracts):
        for ex in extracts:
            self.EChooser.items.append([ex])
        self.RefreshField(self.ctrlChooser)
        self.SetControlValue(self.ctrlChooser, [0])  # set cursor top

    def finished(self):
        pass

    def get_selected_item(self):
        if (self.selected_id == -1) or (self.selected_id >= len(self.EChooser.items)):
            return None
        item_name = self.EChooser.items[self.selected_id][0]
        return choices[item_name]


def fuzzy_search_main():
    # Create form

    choices.clear()
    names.clear()

    gc.collect()

    # Runtime collector.
    # Pros
    # 1. No need to refresh automatically.(When GDB start, libc symbol,PIE's symbol,etc... address will change.When user rename symbol, also.)
    # 1.1. If you want to search library's function, view module list and right-click onto target library. Then click "Analyze module".
    # 2. Action's state is collect (When user start typing, active window is FuzzySearchForm. So filter doesn't works correctly. ex: OpHex is active at Disas view but not active at FuzzySearchForm.)
    # Cons
    # 1. Become slow in case large file.
    # 1.1. Re-generate dictionary isn't matter.(But scoring time will be bigger.)
    # func ptr and icon id

    registered_actions = idaapi.get_registered_actions()
    for action in registered_actions:
        # IDA's bug? tilde exists many times in label. ex) Abort -> ~A~bort
        # So fix it.
        label = idaapi.get_action_label(action).replace("~", "")
        icon = idaapi.get_action_icon(action)[1]
        description = idaapi.get_action_tooltip(action)
        if idaapi.get_action_state(action)[1] > idaapi.AST_ENABLE:
            continue
        choices[label] = Commands(fptr=idaapi.process_ui_action, args=[action], description=description, icon=icon)

    # Functions()
    # Heads()
    for ea, name in idautils.Names():
        if name:
            demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
            name = demangled if demangled else name
            # jump to addr
            choices[name] = Commands(fptr=idc.jumpto, args=[ea], description=f"Jump to {name}", icon=124)

    # Structs
    for _, sid, struct_name in idautils.Structs():
        choices[struct_name] = Commands(
            fptr=idaapi.open_structs_window,
            args=[sid, 0],
            description=f"Jump to Structure definition of {struct_name}",
            icon=52,
        )

        # Struct members
        sptr = idaapi.get_struc(sid)
        ofs = idaapi.get_struc_first_offset(sptr)
        while ofs != idaapi.BADADDR:
            mid = idaapi.get_member_id(sptr, ofs)
            struct_member_name = idaapi.get_member_fullname(mid)
            if struct_member_name:
                choices[struct_member_name] = Commands(
                    fptr=idaapi.open_structs_window,
                    args=[sid, ofs],
                    description=f"Jump to Structure member definition of {struct_member_name}",
                    icon=52,
                )

            ofs = idaapi.get_struc_next_offset(sptr, ofs)

    # Enums
    for idx in range(idaapi.get_enum_qty()):
        eid = idaapi.getn_enum(idx)
        enum_name = idaapi.get_enum_name(eid)
        choices[enum_name] = Commands(
            fptr=idaapi.open_enums_window,
            args=[eid],
            description=f"Jump to Enum definition of {enum_name}",
            icon=1110,
        )

        # Enum members
        class enum_member_cb(idaapi.enum_member_visitor_t):
            def __init__(self, ename):
                super().__init__()
                self.enum_name = ename

            def visit_enum_member(self, cid, _value):
                enum_member_name = idaapi.get_enum_member_name(cid)
                enum_member_name = f"{self.enum_name}.{enum_member_name}"
                choices[enum_member_name] = Commands(
                    fptr=idaapi.open_enums_window,
                    args=[cid],
                    description=f"Jump to Enum member definition of {enum_member_name}",
                    icon=1110,
                )

                return 0

        enum_members = enum_member_cb(enum_name)
        idaapi.for_all_enum_members(eid, enum_members)

    for k, _v in choices.items():
        names.append(k)

    f = FuzzySearchForm()

    # Compile (in order to populate the controls)
    f.Compile()
    f.iStr1.value = ""

    # Execute the form
    ok = f.Execute()

    if ok == 1 and len(f.EChooser.items) > 0:
        cmd = f.get_selected_item()
        if cmd:
            cmd.execute()

    # Dispose the form
    f.Free()


class fuzzy_search_handler(idaapi.action_handler_t):
    def activate(self, ctx):
        fuzzy_search_main()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class FuzzySearchPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Fuzzy search everything for IDA"
    help = "Fuzzy search everything"
    wanted_name = "Fuzzy Search"
    wanted_hotkey = ""
    action_name = "fz:fuzzysearch"

    def init(self):
        print(f"[{self.wanted_name}] plugin loaded")
        idaapi.register_action(
            idaapi.action_desc_t(self.action_name, self.wanted_name, fuzzy_search_handler(), "Shift-Space", "", -1)
        )

        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.action_name)
        print(f"[{self.wanted_name}] plugin terminated")

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return FuzzySearchPlugin()
