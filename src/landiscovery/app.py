"""GTK application and a testable results table model."""
from __future__ import annotations

import ipaddress
import json
import re
import os
import subprocess
import threading
from pathlib import Path

from .engine import ScanEngine, ScanOptions
from .actions import build_action, copy_value, wake_on_lan
from .compare import compare_scans
from .export import export_csv, export_html, export_json
from .i18n import _, set_language
from .mapview import MapView
from .helper import MIN_PREFIX_V4
from .models import ScanResult, open_ports, service_summary
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


_NOT_INSTALLED = re.compile(r"^(.+) not installed$")
_TARGET_FORMATS = ("Accepted targets: an IP address, a network such as "
                   "192.168.1.0/24, or several separated by spaces or commas")


def _error_text(text: str) -> str:
    """Translate the messages produced by the scan engine and the target parser."""
    text = str(text)
    if text.startswith("invalid target:"):
        return (_("Invalid target") + text[len("invalid target"):] + ". "
                + _(_TARGET_FORMATS))
    found = _NOT_INSTALLED.match(text)
    if found:
        return _("{tool} is not installed").format(tool=found.group(1))
    return _(text)


def main() -> int:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, GdkPixbuf, GLib, Gtk, Pango

    set_language("auto")

    def with_placeholder(widget, store, text):
        """Show ``text`` over ``widget`` while ``store`` has no rows."""
        overlay = Gtk.Overlay()
        overlay.add(widget)
        label = Gtk.Label(label=text, halign=Gtk.Align.CENTER, valign=Gtk.Align.CENTER)
        label.get_style_context().add_class("empty-detail")
        label.set_sensitive(False)
        overlay.add_overlay(label)

        def update(*_args):
            label.set_visible(len(store) == 0)

        store.connect("row-inserted", update)
        store.connect("row-deleted", update)
        update()
        return overlay

    class MainWindow(Gtk.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title="LAN Discovery")
            self.set_default_size(1000, 680)
            self.engine = None
            self.model = ResultsModel()
            self.profiles = ProfileStore(default_profiles_path()).load()
            self.store = Store(Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
                               / "landiscovery" / "history.db")
            shell = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            shell.get_style_context().add_class("app-shell")
            self.add(shell)
            header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
            header.get_style_context().add_class("app-header")
            icon = Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(
                str(Path(__file__).parent / "icon.svg"), 42, 42, True))
            header.pack_start(icon, False, False, 0)
            heading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            title = Gtk.Label(label="LAN Discovery", xalign=0)
            title.get_style_context().add_class("app-title")
            heading.pack_start(title, False, False, 0)
            subtitle = Gtk.Label(label=_("Explore your local network"), xalign=0)
            subtitle.get_style_context().add_class("app-subtitle")
            heading.pack_start(subtitle, False, False, 0)
            header.pack_start(heading, True, True, 0)
            shell.pack_start(header, False, False, 0)
            self.stack = Gtk.Stack()
            self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)
            switcher = Gtk.StackSwitcher(stack=self.stack)
            switcher.get_style_context().add_class("app-navigation")
            shell.pack_start(switcher, False, False, 0)
            shell.pack_start(self.stack, True, True, 0)
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
            root.get_style_context().add_class("page-content")
            self.stack.add_titled(root, "scan", _("Scan"))
            controls = Gtk.Box(spacing=10)
            controls.get_style_context().add_class("scan-controls")
            root.pack_start(controls, False, False, 0)
            label = Gtk.Label(label=_("Network targets"))
            controls.pack_start(label, False, False, 0)
            self.targets = Gtk.Entry()
            self.targets.set_placeholder_text("192.168.1.0/24")
            self.targets.set_tooltip_text(_("Enter an IP address or network range"))
            self.targets.set_activates_default(True)
            controls.pack_start(self.targets, True, True, 0)
            self.profile = Gtk.ComboBoxText()
            for name in self.profiles:
                self.profile.append_text(name)
            self.profile.set_active(0)
            self.profile.set_tooltip_text(_("Scan profile"))
            controls.pack_start(self.profile, False, False, 0)
            self.start_button = Gtk.Button(label=_("Start"))
            self.start_button.get_style_context().add_class("suggested-action")
            self.start_button.set_can_default(True)
            self.start_button.connect("clicked", self.start_scan)
            controls.pack_start(self.start_button, False, False, 0)
            self.cancel_button = Gtk.Button(label=_("Cancel"))
            self.cancel_button.set_sensitive(False)
            self.cancel_button.connect("clicked", self.cancel_scan)
            controls.pack_start(self.cancel_button, False, False, 0)
            columns_button = Gtk.Button(label=_("Columns"))
            columns_button.get_style_context().add_class("flat")
            columns_button.connect("clicked", self._columns_menu)
            controls.pack_start(columns_button, False, False, 0)
            self.status = Gtk.Label(label=_("Enter a network target and start a scan"),
                                    xalign=0, wrap=True, max_width_chars=80)
            self.status.set_line_wrap_mode(Pango.WrapMode.WORD_CHAR)
            self.status.get_style_context().add_class("scan-status")
            root.pack_start(self.status, False, False, 0)
            self.reduced_notice = Gtk.Label(
                label=_("Reduced mode: some information is unavailable"), xalign=0)
            self.reduced_notice.get_style_context().add_class("reduced-notice")
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
            self.columns = {}
            for index, name in enumerate(COLUMNS):
                renderer = Gtk.CellRendererText()
                column = Gtk.TreeViewColumn(_(name), renderer, text=index)
                column.set_resizable(True)
                column.set_sort_column_id(index)
                column.set_visible(name in self.model.visible_columns)
                tree.append_column(column)
                self.columns[name] = column
            scroll = Gtk.ScrolledWindow()
            scroll.set_hexpand(True)
            scroll.set_vexpand(True)
            scroll.add(tree)
            self.results_stack = Gtk.Stack()
            self.results_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
            self.results_stack.add_named(scroll, "results")
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            empty.set_halign(Gtk.Align.CENTER)
            empty.set_valign(Gtk.Align.CENTER)
            empty.get_style_context().add_class("empty-state")
            empty_icon = Gtk.Image.new_from_pixbuf(GdkPixbuf.Pixbuf.new_from_file_at_scale(
                str(Path(__file__).parent / "icon.svg"), 64, 64, True))
            empty.pack_start(empty_icon, False, False, 0)
            self.empty_title = Gtk.Label(label=_("Ready to discover"))
            self.empty_title.get_style_context().add_class("empty-title")
            empty.pack_start(self.empty_title, False, False, 0)
            self.empty_detail = Gtk.Label(label=_("Results will appear here after a scan"))
            self.empty_detail.get_style_context().add_class("empty-detail")
            empty.pack_start(self.empty_detail, False, False, 0)
            self.results_stack.add_named(empty, "empty")
            self.results_stack.set_visible_child_name("empty")
            self.results_stack.get_style_context().add_class("results-surface")
            root.pack_start(self.results_stack, True, True, 0)
            self.tree = tree
            self._make_other_pages()
            self.set_default(self.start_button)
            self.show_all()
            self.results_stack.set_visible_child_name("empty")
            self.reduced_notice.hide()
            self._refresh_history()

        def _columns_menu(self, button):
            menu = Gtk.Menu()
            for name, column in self.columns.items():
                item = Gtk.CheckMenuItem(label=_(name))
                item.set_active(column.get_visible())
                item.connect("toggled", self._toggle_column, name)
                menu.append(item)
            menu.show_all()
            menu.popup_at_widget(button, Gdk.Gravity.SOUTH_WEST,
                                 Gdk.Gravity.NORTH_WEST, None)

        def _toggle_column(self, item, name):
            if not item.get_active() and sum(c.get_visible() for c in self.columns.values()) <= 1:
                item.set_active(True)
                return
            self.columns[name].set_visible(item.get_active())
            self.model.set_visible_columns(
                [key for key, column in self.columns.items() if column.get_visible()])

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
            history = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            history.get_style_context().add_class("page-content")
            self.stack.add_titled(history, "history", _("History"))
            self.history_store = Gtk.ListStore(int, str, str, int, str)
            table = Gtk.TreeView(model=self.history_store)
            for index, title in enumerate(("ID", _("Profile"), _("Network targets"),
                                           _("Hosts"), _("Status"))):
                table.append_column(Gtk.TreeViewColumn(title, Gtk.CellRendererText(),
                                                      text=index))
            table.connect("row-activated", self._load_history_scan)
            self.history_table = table
            scroll = Gtk.ScrolledWindow()
            scroll.add(table)
            history.pack_start(with_placeholder(scroll, self.history_store, _("No scans saved")), True, True, 0)
            buttons = Gtk.Box(spacing=8)
            history.pack_start(buttons, False, False, 0)
            for label, callback in (("Refresh", self._refresh_history),
                                    ("Export", self._export_selected),
                                    ("Delete", self._delete_selected)):
                button = Gtk.Button(label=_(label))
                button.connect("clicked", callback)
                buttons.pack_start(button, False, False, 0)

            compare = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            compare.get_style_context().add_class("page-content")
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
            for index, title in enumerate((_("State"), "IP", _("Hostname"), _("Detail"))):
                diff_tree.append_column(Gtk.TreeViewColumn(title, Gtk.CellRendererText(),
                                                           text=index))
            scroll = Gtk.ScrolledWindow()
            scroll.add(diff_tree)
            compare.pack_start(with_placeholder(scroll, self.diff_store, _("Select two scans to compare")), True, True, 0)

            inventory = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            inventory.get_style_context().add_class("page-content")
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
            remove = Gtk.Button(label=_("Delete"))
            remove.connect("clicked", self._delete_device)
            fields.pack_start(remove, False, False, 0)
            self.device_store = Gtk.ListStore(str, str, str, str)
            device_tree = Gtk.TreeView(model=self.device_store)
            for index, name in enumerate((_("Key"), _("Name"), _("Notes"), _("Tags"))):
                device_tree.append_column(Gtk.TreeViewColumn(name, Gtk.CellRendererText(),
                                                             text=index))
            device_tree.connect("row-activated", self._edit_device)
            self.device_tree = device_tree
            scroll = Gtk.ScrolledWindow()
            scroll.add(device_tree)
            inventory.pack_start(with_placeholder(scroll, self.device_store, _("No devices saved")), True, True, 0)

            security = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
            security.get_style_context().add_class("page-content")
            self.stack.add_titled(security, "security", _("Security"))
            self.finding_store = Gtk.ListStore(str, str, str, str)
            findings = Gtk.TreeView(model=self.finding_store)
            for index, name in enumerate((_("Severity"), "IP", _("Title"), _("Detail"))):
                findings.append_column(Gtk.TreeViewColumn(name, Gtk.CellRendererText(),
                                                          text=index))
            scroll = Gtk.ScrolledWindow()
            scroll.add(findings)
            security.pack_start(with_placeholder(scroll, self.finding_store, _("No findings")), True, True, 0)

            map_page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            map_page.get_style_context().add_class("page-content")
            self.stack.add_titled(map_page, "map", _("Map"))
            self.map_view = MapView(on_select=self._select_map_host)
            map_page.pack_start(self.map_view, True, True, 0)

        def _select_map_host(self, node_id):
            host = next((h for h in self.model.rows if h.key == node_id or h.ip == node_id),
                        None)
            if host is None:
                return
            for row in self.table_store:
                if row[0] == host.ip:
                    self.tree.get_selection().select_iter(row.iter)
                    self.stack.set_visible_child_name("scan")
                    break

        def _selected_scan_id(self):
            model, tree_iter = self.history_table.get_selection().get_selected()
            return model[tree_iter][0] if tree_iter is not None else None

        def _refresh_history(self, *_args):
            summaries = self.store.list_scans()
            self.history_store.clear()
            self.old_scan.remove_all()
            self.new_scan.remove_all()
            for item in summaries:
                self.history_store.append((item.id, item.profile, ", ".join(item.targets),
                                           item.host_count, _(item.status)))
                label = f"{item.id} · {item.profile} · " + _("{n} hosts").format(n=item.host_count)
                self.old_scan.append(str(item.id), label)
                self.new_scan.append(str(item.id), label)
            if summaries:
                self.new_scan.set_active(0)
                self.old_scan.set_active(min(1, len(summaries) - 1))
            self.device_store.clear()
            for device in self.store.list_devices():
                self.device_store.append((device.key, device.name, device.note,
                                          ", ".join(device.tags)))

        def _load_history_scan(self, tree, path, *_args):
            scan_id = tree.get_model()[path][0]
            self._show_result(self.store.get_scan(scan_id))
            self.stack.set_visible_child_name("scan")

        def _delete_selected(self, *_args):
            scan_id = self._selected_scan_id()
            if scan_id is not None and self._confirm(_("Delete scan {id}?").format(id=scan_id)):
                self.store.delete_scan(scan_id)
                self._refresh_history()

        def _export_selected(self, *_args):
            scan_id = self._selected_scan_id()
            if scan_id is None:
                return
            dialog = Gtk.FileChooserDialog(title=_("Export"), transient_for=self,
                                           action=Gtk.FileChooserAction.SAVE)
            dialog.add_button(_("Cancel"), Gtk.ResponseType.CANCEL)
            dialog.add_button(_("Save"), Gtk.ResponseType.OK)
            dialog.set_do_overwrite_confirmation(True)
            dialog.set_current_name(f"landiscovery-{scan_id}.html")
            if dialog.run() == Gtk.ResponseType.OK:
                try:
                    path = Path(dialog.get_filename())
                    exporters = {".csv": export_csv, ".json": export_json,
                                 ".html": export_html}
                    exporter = exporters.get(path.suffix.lower())
                    if exporter is None:
                        self._message(_("Use a file name ending in .csv, .json or .html"))
                    else:
                        exporter(self.store.get_scan(scan_id), path)
                except (KeyError, OSError, ValueError) as exc:
                    self._message(str(exc))
            dialog.destroy()

        def _compare_selected(self, *_args):
            old, new = self.old_scan.get_active_id(), self.new_scan.get_active_id()
            if old is None or new is None:
                return
            rows = DiffRows(compare_scans(self.store.get_scan(int(old)),
                                          self.store.get_scan(int(new))))
            self.compare_warning.set_text(
                (_("Comparison is unreliable") + ": " + "; ".join(_(r) for r in rows.reasons))
                if not rows.comparable else "")
            self.diff_store.clear()
            for row in rows.rows:
                self.diff_store.append((_(row.state.title()), row.ip, row.hostname,
                                        row.detail))

        def _save_device(self, *_args):
            values = {name: entry.get_text().strip()
                      for name, entry in self.device_entries.items()}
            if not values["Key"]:
                self._message(_("Device key is required"))
                return
            self.store.set_device(values["Key"], values["Name"], values["Notes"],
                                  [tag.strip() for tag in values["Tags"].split(",")
                                   if tag.strip()])
            self._refresh_history()

        def _delete_device(self, *_args):
            model, tree_iter = self.device_tree.get_selection().get_selected()
            if tree_iter is None:
                return
            key = model[tree_iter][0]
            if self._confirm(_("Delete device {key}?").format(key=key)):
                self.store.delete_device(key)
                for entry in self.device_entries.values():
                    entry.set_text("")
                self._refresh_history()

        def _edit_device(self, tree, path, *_args):
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

        def start_scan(self, *_args):
            try:
                networks = parse_targets(self.targets.get_text())
            except TargetError as exc:
                self._message(_error_text(str(exc)))
                return
            if any(n.version == 4 and n.prefixlen < MIN_PREFIX_V4 for n in networks):
                self._message(_("IPv4 networks wider than /{n} cannot be scanned").format(
                    n=MIN_PREFIX_V4))
                return
            scope = check_scope(networks)
            if not scope.allowed:
                self._message("; ".join(_error_text(r) for r in scope.reasons))
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
            self.table_store.clear()
            self.empty_title.set_text(_("Scan") + "…")
            self.empty_detail.set_text("")
            self.results_stack.set_visible_child_name("empty")

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
                    if not (result.status == "failed" or
                            (result.status == "cancelled" and not result.hosts)):
                        self.store.save_scan(result)
                    GLib.idle_add(self._finished, result, None, diff)
                except Exception as exc:
                    GLib.idle_add(self._finished, None, str(exc), None)

            threading.Thread(target=work, daemon=True).start()

        def _set_progress(self, step, fraction):
            self.status.set_text(_(step))
            self.progress.set_fraction(fraction)
            return False

        def cancel_scan(self, *_args):
            self.cancel_button.set_sensitive(False)
            if self.engine:
                threading.Thread(target=self.engine.cancel, daemon=True).start()

        def _finished(self, result, error, diff):
            self.start_button.set_sensitive(True)
            self.cancel_button.set_sensitive(False)
            self.progress.set_fraction(0)
            if error:
                self.status.set_text(_("Scan failed") + ": " + _error_text(error))
                self.empty_title.set_text(_("Scan failed"))
                self.empty_detail.set_text(_error_text(error))
                self.results_stack.set_visible_child_name("empty")
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
            if result.hosts:
                self.results_stack.set_visible_child_name("results")
            else:
                failed = result.status in ("failed", "cancelled")
                self.empty_title.set_text(_("Scan failed") if result.status == "failed" else
                                          _("Scan cancelled") if failed else _("No hosts found"))
                self.empty_detail.set_text(_("Try another target or scan profile"))
                self.results_stack.set_visible_child_name("empty")
            if result.reduced:
                self.reduced_notice.show()
            else:
                self.reduced_notice.hide()
            for host in self.model.rows:
                self.table_store.append((host.ip, host.hostname, host.mac or "", host.vendor,
                                         "" if host.latency_ms is None else str(host.latency_ms),
                                         ", ".join(str(p.number) for p in open_ports(host)),
                                         service_summary(host), host.os))
            self.finding_store.clear()
            for finding in sorted_findings(result):
                self.finding_store.append((_(finding.severity), finding.host,
                                           finding.title, finding.detail))
            self.map_view.set_topology(result.topology)
            self.status.set_text((_("Scan cancelled") if result.status == "cancelled"
                                  else _("Scan failed") if result.status == "failed"
                                  else _("No hosts found") if not result.hosts
                                  else _("Scan complete")) +
                                 " · " + _("{n} hosts").format(n=len(result.hosts)) +
                                 (" · " + "; ".join(_error_text(w) for w in result.warnings) if result.warnings else ""))

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
