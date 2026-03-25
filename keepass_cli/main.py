"""
KDBX file viewer — Textual TUI
Usage: python viewer.py [kdbx_path]
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import getpass
from pathlib import Path

import appdirs
from pykeepass import PyKeePass
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Static,
    TabbedContent,
    TabPane,
)

from keepass_cli.i18n import _
from keepass_cli.ssh_agent import (
    agent_add_key,
    agent_remove_key,
    get_agent_key_map,
    get_key_comment,
    get_key_fingerprint,
    is_ssh_private_key,
)


def copy_to_clipboard(text: str) -> None:
    """Copy text to system clipboard (macOS/Linux/Windows)."""
    candidates = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip"],
    ]
    for cmd in candidates:
        if shutil.which(cmd[0]) is None:
            continue
        try:
            subprocess.run(
                cmd, input=text.encode(), check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            return
        except Exception:
            continue
    raise RuntimeError(_("No clipboard tool found (install one of: wl-copy/xclip/xsel)"))


# ── TUI widgets ───────────────────────────────────────────────────────────────

class EntryDetail(Static):
    """Widget to display details of a selected entry."""

    DEFAULT_CSS = """
    EntryDetail {
        width: 1fr;
        height: 1fr;
        padding: 1 2;
        border: solid $accent;
        overflow-y: auto;
    }
    """

    @staticmethod
    def _esc(text: str) -> str:
        """Escape Rich markup brackets."""
        return text.replace("[", "\\[")

    def show_entry(self, entry) -> None:
        esc = self._esc
        lines = []
        lines.append(f"[bold cyan]Title:[/]  {esc(entry.title or '')}")
        lines.append(f"[bold cyan]User:[/]   {esc(entry.username or '')}")
        lines.append(f"[bold cyan]Pass:[/]   {esc(entry.password or '')}")
        lines.append(f"[bold cyan]URL:[/]    {esc(entry.url or '')}")
        if entry.notes:
            lines.append("")
            lines.append("[bold cyan]Notes:[/]")
            for note_line in entry.notes.splitlines():
                lines.append(f"  {note_line}")
        if entry.tags:
            lines.append(f"\n[bold cyan]Tags:[/]   {', '.join(entry.tags)}")
        self.update("\n".join(lines))

    def clear(self) -> None:
        self.update("[dim]" + _("Select an entry") + "[/]")


class KdbxViewer(App):
    """Textual app for browsing a KDBX file."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #search-bar {
        dock: top;
        height: auto;
        max-height: 3;
        padding: 0 1;
        background: $surface;
    }
    #search-bar Input {
        width: 100%;
    }
    #passphrase-bar {
        dock: top;
        height: auto;
        max-height: 3;
        padding: 0 1;
        background: $surface;
    }
    #passphrase-bar Input {
        width: 100%;
    }
    TabbedContent {
        height: 1fr;
    }
    #password-view {
        layout: horizontal;
        height: 1fr;
    }
    #group-pane {
        width: 28;
        height: 1fr;
        border: solid $primary;
    }
    #group-pane > Label {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: $text;
        background: $primary-background;
        padding: 0 1;
    }
    #entry-pane {
        width: 32;
        height: 1fr;
        border: solid $secondary;
    }
    #entry-pane > Label {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: $text;
        background: $secondary-background;
        padding: 0 1;
    }
    #detail-pane {
        width: 1fr;
        height: 1fr;
    }
    ListView {
        height: 1fr;
    }
    ListView > ListItem {
        padding: 0 1;
    }
    #ssh-view {
        layout: horizontal;
        height: 1fr;
    }
    #ssh-list-pane {
        width: 40;
        height: 1fr;
        border: solid $primary;
    }
    #ssh-list-pane > Label {
        width: 100%;
        text-align: center;
        text-style: bold;
        color: $text;
        background: $primary-background;
        padding: 0 1;
    }
    #ssh-detail-pane {
        width: 1fr;
        height: 1fr;
    }
    #ssh-detail {
        width: 1fr;
        height: 1fr;
        padding: 1 2;
        border: solid $accent;
        overflow-y: auto;
    }
    """

    BINDINGS = [
        Binding("q", "quit", _("Quit")),
        Binding("1", "show_tab('tab-password')", _("Password"), key_display="1"),
        Binding("2", "show_tab('tab-ssh')", _("SSH Keys"), key_display="2"),
        Binding("tab", "switch_pane", _("Switch Pane")),
        Binding("shift+tab", "switch_pane_back", _("Switch Pane Back")),
        Binding("u", "copy_user", _("Copy ID")),
        Binding("p", "copy_pass", _("Copy PW")),
        Binding("h", "copy_host", _("Copy Host")),
        Binding("l", "copy_url", _("Copy URL")),
        Binding("slash", "focus_search", _("Search"), key_display="/"),
        Binding("escape", "go_back", _("Back"), show=False),
        Binding("left", "go_back", _("Back"), show=False),
        Binding("a", "ssh_add", _("Add to Agent")),
        Binding("d", "ssh_delete", _("Remove from Agent")),
    ]

    def __init__(self, kp: PyKeePass) -> None:
        super().__init__()
        self.kp = kp
        self.groups: list = []
        self.entries_map: dict[str, list] = {}
        self._current_entry = None
        self._search_query = ""
        self._ssh_keys: list = []
        self._current_ssh_idx: int = -1
        self._agent_map: dict[str, bytes] = {}
        self._pending_add_idx: int = -1
        self._build_data()

    def _build_data(self) -> None:
        """Organise KDBX data into group/entry structure."""
        self.groups.clear()
        self.entries_map.clear()
        root = self.kp.root_group
        for group in sorted(root.subgroups, key=lambda g: g.name or ""):
            name = group.name or _("(no name)")
            self.groups.append(name)
            self.entries_map[name] = sorted(
                group.entries, key=lambda e: e.title or ""
            )
        root_entries = [e for e in root.entries if e.title]
        if root_entries:
            self.groups.insert(0, "(Root)")
            self.entries_map["(Root)"] = sorted(
                root_entries, key=lambda e: e.title or ""
            )
        # Collect SSH keys (attachments) — filter SSH private keys only
        self._ssh_keys.clear()
        self._agent_map = get_agent_key_map()
        agent_fps = set(self._agent_map.keys())
        for att in self.kp.attachments:
            fname = att.filename or ""
            if fname == "KeeAgent.settings" or fname.endswith(".pub"):
                continue
            if not is_ssh_private_key(att.binary):
                continue
            entry = att.entry
            entry_title = entry.title or _("(no title)")
            group_name = entry.group.name if entry.group else ""
            fp = get_key_fingerprint(att.binary)
            registered = fp in agent_fps if fp else False
            self._ssh_keys.append((fname, entry_title, group_name, att, fp, registered))

    def _filtered_groups(self) -> list[str]:
        if not self._search_query:
            return list(self.groups)
        q = self._search_query.lower()
        result = []
        for g in self.groups:
            if q in g.lower():
                result.append(g)
                continue
            entries = self.entries_map.get(g, [])
            if any(self._entry_matches(e, q) for e in entries):
                result.append(g)
        return result

    def _filtered_entries(self, group_name: str) -> list:
        entries = self.entries_map.get(group_name, [])
        if not self._search_query:
            return entries
        q = self._search_query.lower()
        if q in group_name.lower():
            return entries
        return [e for e in entries if self._entry_matches(e, q)]

    @staticmethod
    def _entry_matches(entry, query: str) -> bool:
        for field in (entry.title, entry.username, entry.url):
            if field and query in field.lower():
                return True
        return False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="search-bar"):
            yield Input(placeholder=_("Enter search term and press Enter (Esc: close)"), id="search-input")
        with Horizontal(id="passphrase-bar"):
            yield Input(
                placeholder=_("Enter SSH key passphrase (Esc: cancel)"),
                id="passphrase-input",
                password=True,
            )
        with TabbedContent(_("Passwords"), _("SSH Keys"), initial="tab-password"):
            with TabPane(_("Passwords"), id="tab-password"):
                with Horizontal(id="password-view"):
                    with Vertical(id="group-pane"):
                        yield Label(_("Groups"))
                        yield ListView(id="group-list")
                    with Vertical(id="entry-pane"):
                        yield Label(_("Entries"))
                        yield ListView(id="entry-list")
                    with Vertical(id="detail-pane"):
                        yield EntryDetail(id="detail")
            with TabPane(_("SSH Keys"), id="tab-ssh"):
                with Horizontal(id="ssh-view"):
                    with Vertical(id="ssh-list-pane"):
                        yield Label(_("SSH Key List"))
                        yield ListView(id="ssh-list")
                    with Vertical(id="ssh-detail-pane"):
                        yield Static("", id="ssh-detail")
        yield Footer()

    def on_mount(self) -> None:
        from textual.widgets import Tabs
        self.query_one("#search-bar").display = False
        self.query_one("#passphrase-bar").display = False
        self.query_one(Tabs).can_focus = False
        detail = self.query_one("#detail", EntryDetail)
        detail.clear()
        self._refresh_group_list()
        self._refresh_ssh_list(focus=False)
        self.refresh_bindings()
        group_list = self.query_one("#group-list", ListView)
        group_list.focus()

    def _refresh_group_list(self) -> None:
        group_list = self.query_one("#group-list", ListView)
        group_list.clear()
        filtered = self._filtered_groups()
        for g in filtered:
            group_list.append(ListItem(Label(g), name=g))
        if filtered:
            group_list.index = 0
            self._load_entries(filtered[0])
        else:
            entry_list = self.query_one("#entry-list", ListView)
            entry_list.clear()
            detail = self.query_one("#detail", EntryDetail)
            self._current_entry = None
            detail.clear()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input":
            self._search_query = event.value.strip()
            self._refresh_group_list()
            self.query_one("#search-bar").display = False
            group_list = self.query_one("#group-list", ListView)
            group_list.focus()
            if self._search_query:
                self.notify(_("Search: \"{query}\"").format(query=self._search_query), timeout=2)
        elif event.input.id == "passphrase-input":
            passphrase = event.value
            event.input.value = ""
            self.query_one("#passphrase-bar").display = False
            self._do_ssh_add(passphrase)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id == "group-list" and event.item is not None:
            self._load_entries(event.item.name or "")
        elif event.list_view.id == "entry-list" and event.item is not None:
            self._show_detail(event.item.name or "")
        elif event.list_view.id == "ssh-list" and event.item is not None:
            self._show_ssh_detail(int(event.item.name))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "group-list" and event.item is not None:
            self._load_entries(event.item.name or "")
            self.query_one("#entry-list", ListView).focus()
        elif event.list_view.id == "entry-list" and event.item is not None:
            self._show_detail(event.item.name or "")

    def _load_entries(self, group_name: str) -> None:
        entry_list = self.query_one("#entry-list", ListView)
        entry_list.clear()
        entries = self._filtered_entries(group_name)
        for i, entry in enumerate(entries):
            key = f"{group_name}::{i}"
            entry_list.append(ListItem(Label(entry.title or _("(no title)"), markup=False), name=key))
        detail = self.query_one("#detail", EntryDetail)
        if entries:
            self._current_entry = entries[0]
            detail.show_entry(entries[0])
            self.call_after_refresh(lambda: setattr(entry_list, "index", 0))
        else:
            self._current_entry = None
            detail.clear()

    def _show_detail(self, key: str) -> None:
        if "::" not in key:
            return
        group_name, idx_str = key.rsplit("::", 1)
        idx = int(idx_str)
        entries = self._filtered_entries(group_name)
        if 0 <= idx < len(entries):
            self._current_entry = entries[idx]
            self.query_one("#detail", EntryDetail).show_entry(entries[idx])

    def _copy_field(self, value, label: str) -> None:
        if not value:
            self.notify(_("{label} value is empty").format(label=label), severity="warning", timeout=2)
            return
        try:
            copy_to_clipboard(value)
            self.notify(f"{label} copied", severity="information", timeout=2)
        except Exception:
            self.notify("clipboard copy failed", severity="error", timeout=2)

    # ── SSH key tab ───────────────────────────────────────────────────────────

    def _refresh_ssh_list(self, restore_idx: int = -1, focus: bool = True) -> None:
        ssh_list = self.query_one("#ssh-list", ListView)
        ssh_list.clear()
        ssh_detail = self.query_one("#ssh-detail", Static)
        if not self._ssh_keys:
            ssh_detail.update("[dim]" + _("No SSH keys registered") + "[/]")
            self._current_ssh_idx = -1
            return
        for i, (_fn, entry_title, group_name, _att, _fp, registered) in enumerate(self._ssh_keys):
            status = "[green]●[/]" if registered else "[red]○[/]"
            esc_group = group_name.replace("[", "\\[")
            esc_title = entry_title.replace("[", "\\[")
            display = f"{status} {esc_group} / {esc_title}"
            ssh_list.append(ListItem(Label(display), name=str(i)))
        idx = max(0, min(restore_idx, len(self._ssh_keys) - 1))
        self._show_ssh_detail(idx)

        def _restore() -> None:
            ssh_list.index = idx
            if focus:
                ssh_list.focus()

        self.call_after_refresh(_restore)

    def _show_ssh_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._ssh_keys):
            return
        filename, entry_title, group_name, att, fp, registered = self._ssh_keys[idx]
        self._current_ssh_idx = idx
        status = "[bold green]" + _("Registered") + "[/]" if registered else "[bold red]" + _("Not registered") + "[/]"
        esc_fn = filename.replace("[", "\\[")
        esc_group = group_name.replace("[", "\\[")
        esc_title = entry_title.replace("[", "\\[")
        lines = [
            f"[bold cyan]{_('Filename:')}[/]       {esc_fn}",
            f"[bold cyan]{_('Entry:')}[/]    {esc_group} / {esc_title}",
            f"[bold cyan]{_('Size:')}[/]         {len(att.binary)} bytes",
            f"[bold cyan]Fingerprint:[/]  {fp or _('(unknown)')}",
            f"[bold cyan]{_('Agent status:')}[/]   {status}",
        ]
        self.query_one("#ssh-detail", Static).update("\n".join(lines))

    def _refresh_ssh_state(self) -> None:
        """Re-query Agent state and refresh list (preserving selection)."""
        saved_idx = self._current_ssh_idx
        self._agent_map = get_agent_key_map()
        agent_fps = set(self._agent_map.keys())
        self._ssh_keys = [
            (fn, et, gn, at, f, f in agent_fps if f else False)
            for fn, et, gn, at, f, _ in self._ssh_keys
        ]
        self._refresh_ssh_list(restore_idx=saved_idx)

    def _do_ssh_add(self, passphrase: str | None = None) -> None:
        """Add currently selected SSH key to Agent."""
        idx = self._pending_add_idx
        self._pending_add_idx = -1
        if idx < 0 or idx >= len(self._ssh_keys):
            return
        fname, entry_title, group_name, att, _fp, _reg = self._ssh_keys[idx]
        comment = get_key_comment(att.binary, passphrase=passphrase) or f"@{fname}"
        ok, err = agent_add_key(att.binary, passphrase=passphrase, comment=comment)
        if ok:
            fn, et, gn, at, fp, reg = self._ssh_keys[idx]
            if fp is None:
                fp = get_key_fingerprint(at.binary, passphrase=passphrase)
                self._ssh_keys[idx] = (fn, et, gn, at, fp, reg)
            self.notify(_("Added key {group}/{title} to Agent").format(group=group_name, title=entry_title), timeout=2)
            self._refresh_ssh_state()
        elif err == "passphrase_required":
            if passphrase is None and att.entry.password:
                self._pending_add_idx = idx
                self._do_ssh_add(passphrase=att.entry.password)
                return
            self._pending_add_idx = idx
            self.query_one("#passphrase-bar").display = True
            pp_input = self.query_one("#passphrase-input", Input)
            pp_input.value = ""
            pp_input.focus()
            self.notify(_("This key requires a passphrase"), severity="warning", timeout=2)
        else:
            self.notify(_("Failed to add to agent: {err}").format(err=err), severity="error", timeout=3)

    # ── Tab switching / bindings ──────────────────────────────────────────────

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id
        if tab_id == "tab-ssh":
            self.query_one("#ssh-list", ListView).focus()
        elif tab_id == "tab-password":
            group_list = self.query_one("#group-list", ListView)
            group_list.index = 0
            group_list.focus()
        self.refresh_bindings()

    def check_action(self, action: str, parameters: tuple) -> bool | None:
        is_ssh = self._is_ssh_tab_active()
        password_actions = {"copy_user", "copy_pass", "copy_host", "copy_url", "focus_search"}
        ssh_actions = {"ssh_add", "ssh_delete"}
        if action in password_actions:
            return not is_ssh
        if action in ssh_actions:
            return is_ssh
        return True

    def _is_ssh_tab_active(self) -> bool:
        return self.query_one(TabbedContent).active == "tab-ssh"

    # ── Action handlers ───────────────────────────────────────────────────────

    def action_copy_user(self) -> None:
        if self._current_entry:
            self._copy_field(self._current_entry.username, "ID")

    def action_copy_pass(self) -> None:
        if self._current_entry:
            self._copy_field(self._current_entry.password, "Password")

    def action_copy_host(self) -> None:
        if self._current_entry and self._current_entry.notes:
            for line in self._current_entry.notes.splitlines():
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    self._copy_field(host, "Host")
                    return
        if self._current_entry and self._current_entry.url:
            self._copy_field(self._current_entry.url, "Host(URL)")
        else:
            self.notify(_("No Host information"), severity="warning", timeout=2)

    def action_copy_url(self) -> None:
        if self._current_entry:
            self._copy_field(self._current_entry.url, "URL")

    def action_ssh_add(self) -> None:
        if not self._is_ssh_tab_active():
            return
        if self._current_ssh_idx < 0 or self._current_ssh_idx >= len(self._ssh_keys):
            self.notify(_("No SSH key to add"), severity="warning", timeout=2)
            return
        _, _, _, _, _, registered = self._ssh_keys[self._current_ssh_idx]
        if registered:
            self.notify(_("Key is already registered in Agent"), severity="warning", timeout=2)
            return
        self._pending_add_idx = self._current_ssh_idx
        self._do_ssh_add()

    def action_ssh_delete(self) -> None:
        if not self._is_ssh_tab_active():
            return
        if self._current_ssh_idx < 0 or self._current_ssh_idx >= len(self._ssh_keys):
            self.notify(_("No SSH key to remove"), severity="warning", timeout=2)
            return
        _fname, entry_title, group_name, _att, fp, registered = self._ssh_keys[self._current_ssh_idx]
        if not registered:
            self.notify(_("Key is not registered in Agent"), severity="warning", timeout=2)
            return
        if not fp or fp not in self._agent_map:
            self.notify(_("Key not found in Agent"), severity="error", timeout=2)
            return
        blob = self._agent_map[fp]
        if agent_remove_key(blob):
            self.notify(_("Removed key {group}/{title} from Agent").format(group=group_name, title=entry_title), timeout=2)
            self._refresh_ssh_state()
        else:
            self.notify(_("Failed to remove key from Agent"), severity="error", timeout=2)

    def action_focus_search(self) -> None:
        self.query_one("#search-bar").display = True
        self.query_one("#search-input", Input).focus()

    def action_go_back(self) -> None:
        # Cancel if passphrase input is active
        pp_input = self.query_one("#passphrase-input", Input)
        if pp_input.has_focus:
            pp_input.value = ""
            self.query_one("#passphrase-bar").display = False
            self._pending_add_idx = -1
            self.query_one("#ssh-list", ListView).focus()
            return
        # Close search if active
        search_input = self.query_one("#search-input", Input)
        if search_input.has_focus:
            search_input.value = ""
            self.query_one("#search-bar").display = False
            if self._search_query:
                self._search_query = ""
                self._refresh_group_list()
                self.notify(_("Search reset"), timeout=2)
            self.query_one("#group-list", ListView).focus()
            return
        # Move from entry list to group list
        entry_list = self.query_one("#entry-list", ListView)
        if entry_list.has_focus:
            self.query_one("#group-list", ListView).focus()

    def action_switch_pane(self) -> None:
        group_list = self.query_one("#group-list", ListView)
        entry_list = self.query_one("#entry-list", ListView)
        if group_list.has_focus:
            entry_list.focus()
        else:
            group_list.focus()

    def action_switch_pane_back(self) -> None:
        self.action_switch_pane()


def _default_kdbx() -> Path:
    """Return path to database.kdbx in the appdirs data directory.

    On first run, copies the bundled file to the data directory.
    """
    data_dir = Path(appdirs.user_data_dir("keepass_cli"))
    data_dir.mkdir(parents=True, exist_ok=True)
    dest = data_dir / "database.kdbx"
    if not dest.exists():
        bundled = Path(__file__).parent / "database.kdbx"
        if bundled.exists():
            shutil.copy2(bundled, dest)
    return dest


def main() -> None:
    kdbx_path = Path(sys.argv[1]) if len(sys.argv) > 1 else _default_kdbx()
    if not kdbx_path.exists():
        print(_("File not found: {path}").format(path=kdbx_path))
        sys.exit(1)

    master_pw = getpass.getpass(_("Master password: "))
    try:
        kp = PyKeePass(str(kdbx_path), password=master_pw)
    except Exception as e:
        print(_("Failed to open KDBX: {err}").format(err=e))
        sys.exit(1)

    app = KdbxViewer(kp)
    app.title = f"KDBX Viewer — {kdbx_path.name}"
    app.run()


if __name__ == "__main__":
    main()
