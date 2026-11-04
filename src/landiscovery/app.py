"""GTK application and a testable results table model."""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import threading
from pathlib import Path

from .engine import ScanEngine, ScanOptions
from .actions import build_action, copy_value, wake_on_lan
from .compare import compare_scans
from .export import export_csv, export_html, export_json
from .i18n import _, set_language
from .models import ScanResult
from .profiles import ProfileStore, default_profiles_path
from .store import Store
from .targets import TargetError, check_scope, parse_targets
from .views import DiffRows, sorted_findings

COLUMNS = ("IP", "Hostname", "MAC", "Vendor", "Latency", "Ports", "Services", "OS")


def default_ui_path() -> Path:
    root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "landiscovery" / "ui.json"


class ResultsModel:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else default_ui_path()
        self.rows = []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            visible = data.get("visible_columns", list(COLUMNS))
            self.visible_columns = [name for name in COLUMNS if name in visible]
        except (OSError, ValueError, AttributeError):
            self.visible_columns = list(COLUMNS)

    def load(self, result: ScanResult) -> None:
        self.rows = list(result.hosts)

    def sort(self, column: str, descending: bool = False) -> None:
        key = {
            "IP": lambda h: (ipaddress.ip_address(h.ip).version,
                             int(ipaddress.ip_address(h.ip))),
            "Hostname": lambda h: h.hostname.casefold(),
            "MAC": lambda h: (h.mac or "").casefold(),
            "Vendor": lambda h: h.vendor.casefold(),
            "Latency": lambda h: h.latency_ms if h.latency_ms is not None else -1,
            "Ports": lambda h: len(h.ports),
            "Services": lambda h: ", ".join(h.services).casefold(),
            "OS": lambda h: h.os.casefold(),
        }.get(column)
        if key is None:
            raise ValueError(f"unknown column: {column}")
        self.rows.sort(key=key, reverse=descending)

    def set_visible_columns(self, columns: list[str]) -> None:
        self.visible_columns = [name for name in COLUMNS if name in columns]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"visible_columns": self.visible_columns}),
                             encoding="utf-8")


def main() -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GLib, Gtk

    set_language("auto")

    class MainWindow(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title="landiscovery")
            self.set_default_size(1000, 620)
            self.engine = None
            self.model = ResultsModel()
            self.profiles = ProfileStore(default_profiles_path()).load()
            self.store = Store(Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
                               / "landiscovery" / "history.db")
            shell = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            shell.set_border_width(12)
            self.add(shell)
            self.stack = Gtk.Stack()
            self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
            switcher = Gtk.StackSwitcher(stack=self.stack)
            shell.pack_start(switcher, False, False, 0)
            shell.pack_start(self.stack, True, True, 0)
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.stack.add_titled(root, "scan", _("Scan"))
            controls = Gtk.Box(spacing=8)
            root.pack_start(controls, False, False, 0)
            label = Gtk.Label(label=_("Network targets"))
            controls.pack_start(label, False, False, 0)
            self.targets = Gtk.Entry()
            self.targets.set_placeholder_text("192.168.1.0/24")
            self.targets.set_activates_default(True)
            controls.pack_start(self.targets, True, True, 0)
            self.profile = Gtk.ComboBoxText()
            for name in self.profiles:
                self.profile.append_text(name)
            self.profile.set_active(0)
            controls.pack_start(self.profile, False, False, 0)
            self.start_button = Gtk.Button(label=_("Start"))
            self.start_button.set_can_default(True)
            self.start_button.connect("clicked", self.start_scan)
            controls.pack_start(self.start_button, False, False, 0)
            self.cancel_button = Gtk.Button(label=_("Cancel"))
            self.cancel_button.set_sensitive(False)
            self.cancel_button.connect("clicked", self.cancel_scan)
            controls.pack_start(self.cancel_button, False, False, 0)
            self.status = Gtk.Label(label=_("No hosts found"), xalign=0)
            root.pack_start(self.status, False, False, 0)
            self.reduced_notice = Gtk.Label(
                label=_("Reduced mode: some information is unavailable"), xalign=0)
            self.reduced_notice.set_no_show_all(True)
            root.pack_start(self.reduced_notice, False, False, 0)
            self.progress = Gtk.ProgressBar()
            root.pack_start(self.progress, False, False, 0)
            self.table_store = Gtk.ListStore(*([str] * len(COLUMNS)))
            def ip_sort(model, left, right, _):
                a = ipaddress.ip_address(model.get_value(left, 0))
                b = ipaddress.ip_address(model.get_value(right, 0))
                av, bv = (a.version, int(a)), (b.version, int(b))
                return (av > bv) - (av < bv)
            self.table_store.set_sort_func(0, ip_sort, None)
            tree = Gtk.TreeView(model=self.table_store)
            tree.set_headers_clickable(True)
            tree.connect("button-press-event", self._host_menu)
            for index, name in enumerate(COLUMNS):
                renderer = Gtk.CellRendererText()
                column = Gtk.TreeViewColumn(_(name), renderer, text=index)
                column.set_resizable(True)
                column.set_sort_column_id(index)
                tree.append_column(column)
            scroll = Gtk.ScrolledWindow()
            scroll.set_hexpand(True)
            scroll.set_vexpand(True)
            scroll.add(tree)
            root.pack_start(scroll, True, True, 0)
            self.tree = tree
            self._make_other_pages()
            self.set_default(self.start_button)
            self.show_all()
            self.reduced_notice.hide()
            self._refresh_history()

        def _host_menu(self, tree, event):
            if event.button != 3:
                return False
            selected = tree.get_path_at_pos(int(event.x), int(event.y))
            if selected is None:
                return False
            path = selected[0]
            tree.get_selection().select_path(path)
            ip = self.table_store[path][0]
            host = next((h for h in self.model.rows if h.ip == ip), None)
            if host is None:
                return False
            menu = Gtk.Menu()
            for label, kind in (("SSH", "ssh"), ("RDP", "rdp"),
                                ("Browser", "browser"), ("Ping", "ping"),
                                ("Traceroute", "traceroute")):
                item = Gtk.MenuItem(label=_(label))
                item.connect("activate", self._run_host_action, kind, host)
                menu.append(item)
            if host.mac:
                item = Gtk.MenuItem(label=_("Wake on LAN"))
                item.connect("activate", self._run_host_action, "wol", host)
                menu.append(item)
            item = Gtk.MenuItem(label=_("Copy IP"))
            item.connect("activate", lambda *_: Gtk.Clipboard.get(
                Gdk.SELECTION_CLIPBOARD).set_text(copy_value(host.ip), -1))
            menu.append(item)
            menu.show_all()
            menu.popup_at_pointer(event)
            return True

        def _make_other_pages(self):
            history = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.stack.add_titled(history, "history", _("History"))
            self.history_store = Gtk.ListStore(int, str, str, int, str)
            table = Gtk.TreeView(model=self.history_store)
            for index, title in enumerate(("ID", _("Profile"), _("Network targets"),
                                           "Hosts", "Status")):
                table.append_column(Gtk.TreeViewColumn(title, Gtk.CellRendererText(),
                                                      text=index))
            table.connect("row-activated", self._load_history_scan)
            self.history_table = table
            scroll = Gtk.ScrolledWindow()
            scroll.add(table)
            history.pack_start(scroll, True, True, 0)
            buttons = Gtk.Box(spacing=8)
            history.pack_start(buttons, False, False, 0)
            for label, callback in (("Refresh", self._refresh_history),
                                    ("Export", self._export_selected),
                                    ("Delete", self._delete_selected)):
                button = Gtk.Button(label=_(label))
                button.connect("clicked", callback)
                buttons.pack_start(button, False, False, 0)

            compare = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.stack.add_titled(compare, "compare", _("Compare"))
            choices = Gtk.Box(spacing=8)
            compare.pack_start(choices, False, False, 0)
            self.old_scan = Gtk.ComboBoxText()
            self.new_scan = Gtk.ComboBoxText()
            choices.pack_start(self.old_scan, False, False, 0)
            choices.pack_start(self.new_scan, False, False, 0)
            go = Gtk.Button(label=_("Compare"))
            go.connect("clicked", self._compare_selected)
            choices.pack_start(go, False, False, 0)
            self.compare_warning = Gtk.Label(xalign=0)
            compare.pack_start(self.compare_warning, False, False, 0)
            self.diff_store = Gtk.ListStore(str, str, str, str)
            diff_tree = Gtk.TreeView(model=self.diff_store)
            for index, title in enumerate(("State", "IP", _("Hostname"), "Detail")):
                diff_tree.append_column(Gtk.TreeViewColumn(title, Gtk.CellRendererText(),
                                                           text=index))
            scroll = Gtk.ScrolledWindow()
            scroll.add(diff_tree)
            compare.pack_start(scroll, True, True, 0)

            inventory = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.stack.add_titled(inventory, "inventory", _("Inventory"))
            fields = Gtk.Box(spacing=8)
            inventory.pack_start(fields, False, False, 0)
            self.device_entries = {}
            for name in ("Key", "Name", "Notes", "Tags"):
                entry = Gtk.Entry()
                entry.set_placeholder_text(_(name))
                fields.pack_start(entry, True, True, 0)
                self.device_entries[name] = entry
            save = Gtk.Button(label=_("Save"))
            save.connect("clicked", self._save_device)
            fields.pack_start(save, False, False, 0)
            self.device_store = Gtk.ListStore(str, str, str, str)
            device_tree = Gtk.TreeView(model=self.device_store)
            for index, name in enumerate(("Key", _("Name"), _("Notes"), _("Tags"))):
                device_tree.append_column(Gtk.TreeViewColumn(name, Gtk.CellRendererText(),
                                                             text=index))
            device_tree.connect("row-activated", self._edit_device)
            scroll = Gtk.ScrolledWindow()
            scroll.add(device_tree)
            inventory.pack_start(scroll, True, True, 0)

            security = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.stack.add_titled(security, "security", _("Security"))
            self.finding_store = Gtk.ListStore(str, str, str, str)
            findings = Gtk.TreeView(model=self.finding_store)
            for index, name in enumerate(("Severity", "IP", "Title", "Detail")):
                findings.append_column(Gtk.TreeViewColumn(name, Gtk.CellRendererText(),
                                                          text=index))
            scroll = Gtk.ScrolledWindow()
            scroll.add(findings)
            security.pack_start(scroll, True, True, 0)

        def _selected_scan_id(self):
            model, tree_iter = self.history_table.get_selection().get_selected()
            return model[tree_iter][0] if tree_iter is not None else None

        def _refresh_history(self, *_):
            summaries = self.store.list_scans()
            self.history_store.clear()
            self.old_scan.remove_all()
            self.new_scan.remove_all()
            for item in summaries:
                self.history_store.append((item.id, item.profile, ", ".join(item.targets),
                                           item.host_count, item.status))
                label = f"{item.id} · {item.profile} · {item.host_count} hosts"
                self.old_scan.append(str(item.id), label)
                self.new_scan.append(str(item.id), label)
            if summaries:
                self.new_scan.set_active(0)
                self.old_scan.set_active(min(1, len(summaries) - 1))
            self.device_store.clear()
            for device in self.store.list_devices():
                self.device_store.append((device.key, device.name, device.note,
                                          ", ".join(device.tags)))

        def _load_history_scan(self, tree, path, *_):
            scan_id = tree.get_model()[path][0]
            self._show_result(self.store.get_scan(scan_id))
            self.stack.set_visible_child_name("scan")

        def _delete_selected(self, *_):
            scan_id = self._selected_scan_id()
            if scan_id is not None and self._confirm(f"Delete scan {scan_id}?"):
                self.store.delete_scan(scan_id)
                self._refresh_history()

        def _export_selected(self, *_):
            scan_id = self._selected_scan_id()
            if scan_id is None:
                return
            dialog = Gtk.FileChooserDialog(title=_("Export"), transient_for=self,
                                           action=Gtk.FileChooserAction.SAVE)
            dialog.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
            dialog.add_button(_("Save"), Gtk.ResponseType.OK)
            dialog.set_current_name(f"landiscovery-{scan_id}.html")
            if dialog.run() == Gtk.ResponseType.OK:
                try:
                    path = Path(dialog.get_filename())
                    exporters = {".csv": export_csv, ".json": export_json,
                                 ".html": export_html}
                    exporters[path.suffix.lower()](self.store.get_scan(scan_id), path)
                except (KeyError, OSError, ValueError) as exc:
                    self._message(str(exc))
            dialog.destroy()

        def _compare_selected(self, *_):
            old, new = self.old_scan.get_active_id(), self.new_scan.get_active_id()
            if old is None or new is None:
                return
            rows = DiffRows(compare_scans(self.store.get_scan(int(old)),
                                          self.store.get_scan(int(new))))
            self.compare_warning.set_text(
                (_("Comparison is unreliable") + ": " + "; ".join(rows.reasons))
                if not rows.comparable else "")
            self.diff_store.clear()
            for row in rows.rows:
                self.diff_store.append((_(row.state.title()), row.ip, row.hostname,
                                        row.detail))

        def _save_device(self, *_):
            values = {name: entry.get_text().strip()
                      for name, entry in self.device_entries.items()}
            if not values["Key"]:
                self._message("Device key is required")
                return
            self.store.set_device(values["Key"], values["Name"], values["Notes"],
                                  [tag.strip() for tag in values["Tags"].split(",")
                                   if tag.strip()])
            self._refresh_history()

        def _edit_device(self, tree, path, *_):
            row = tree.get_model()[path]
            for entry, value in zip(self.device_entries.values(), row):
                entry.set_text(value)

        def _run_host_action(self, _item, kind, host):
            try:
                if kind == "wol":
                    wake_on_lan(host.mac)
                else:
                    subprocess.Popen(build_action(kind, host), start_new_session=True)
            except (OSError, ValueError) as exc:
                self._message(str(exc))

        def _message(self, text, kind=Gtk.MessageType.ERROR):
            dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=kind,
                                       buttons=Gtk.ButtonsType.OK, text=text)
            dialog.run()
            dialog.destroy()

        def _confirm(self, text):
            dialog = Gtk.MessageDialog(transient_for=self, modal=True,
                                       message_type=Gtk.MessageType.QUESTION,
                                       buttons=Gtk.ButtonsType.YES_NO, text=text)
            accepted = dialog.run() == Gtk.ResponseType.YES
            dialog.destroy()
            return accepted

        def start_scan(self, *_):
            try:
                networks = parse_targets(self.targets.get_text())
            except TargetError as exc:
                self._message(str(exc))
                return
            scope = check_scope(networks)
            if not scope.allowed:
                self._message("; ".join(scope.reasons))
                return
            if scope.needs_confirmation and not self._confirm(_(
                    "This scan covers a public or large network. Continue?")):
                return
            profile = self.profiles[self.profile.get_active_text()]
            community = None
            if profile.snmp:
                dialog = Gtk.Dialog(title=_("SNMP community"), transient_for=self,
                                    modal=True)
                dialog.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
                dialog.add_button(_("Start"), Gtk.ResponseType.OK)
                entry = Gtk.Entry()
                entry.set_visibility(False)
                entry.set_invisible_char("●")
                dialog.get_content_area().pack_start(entry, True, True, 12)
                entry.show()
                if dialog.run() == Gtk.ResponseType.OK:
                    community = entry.get_text()
                dialog.destroy()
            self.engine = ScanEngine()
            self.start_button.set_sensitive(False)
            self.cancel_button.set_sensitive(True)
            self.status.set_text(_("Scan") + "…")

            def progress(step, fraction):
                GLib.idle_add(self._set_progress, step, fraction)

            def work():
                try:
                    result = self.engine.scan(networks, profile,
                                              ScanOptions(snmp_community=community),
                                              on_progress=progress)
                    previous = self.store.list_scans()
                    diff = (compare_scans(self.store.get_scan(previous[0].id), result)
                            if previous else None)
                    self.store.save_scan(result)
                    GLib.idle_add(self._finished, result, None, diff)
                except Exception as exc:
                    GLib.idle_add(self._finished, None, str(exc), None)

            threading.Thread(target=work, daemon=True).start()

        def _set_progress(self, step, fraction):
            self.status.set_text(step)
            self.progress.set_fraction(fraction)
            return False

        def cancel_scan(self, *_):
            self.cancel_button.set_sensitive(False)
            if self.engine:
                threading.Thread(target=self.engine.cancel, daemon=True).start()

        def _finished(self, result, error, diff):
            self.start_button.set_sensitive(True)
            self.cancel_button.set_sensitive(False)
            self.progress.set_fraction(0)
            if error:
                self.status.set_text(_("Scan failed") + ": " + error)
                return False
            self._show_result(result)
            if diff and diff.comparable and diff.new_hosts:
                self.status.set_text(self.status.get_text() +
                                     f" · {len(diff.new_hosts)} " + _("New"))
            self._refresh_history()
            return False

        def _show_result(self, result):
            self.model.load(result)
            self.table_store.clear()
            if result.reduced:
                self.reduced_notice.show()
            else:
                self.reduced_notice.hide()
            for host in self.model.rows:
                self.table_store.append((host.ip, host.hostname, host.mac or "", host.vendor,
                                         "" if host.latency_ms is None else str(host.latency_ms),
                                         ", ".join(str(p.number) for p in host.ports),
                                         ", ".join(host.services), host.os))
            self.finding_store.clear()
            for finding in sorted_findings(result):
                self.finding_store.append((finding.severity, finding.host,
                                           finding.title, finding.detail))
            self.status.set_text((_("Scan cancelled") if result.status == "cancelled"
                                  else _("Scan failed") if result.status == "failed"
                                  else _("No hosts found") if not result.hosts
                                  else _("Scan complete")) +
                                 f" · {len(result.hosts)} hosts" +
                                 (" · " + "; ".join(result.warnings) if result.warnings else ""))

    class Application(Gtk.Application):
        def __init__(self):
            super().__init__(application_id="org.syslinuxos.landiscovery")

        def do_activate(self):
            asset_dir = Path(__file__).parent
            provider = Gtk.CssProvider()
            provider.load_from_path(str(asset_dir / "style.css"))
            Gtk.StyleContext.add_provider_for_screen(
                Gdk.Screen.get_default(),
                provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            window = self.get_active_window()
            if window is None:
                window = MainWindow(self)
                window.set_icon_from_file(str(asset_dir / "icon.svg"))
            window.present()

    return Application().run([])
