"""GTK application and a testable results table model."""
from __future__ import annotations

import ipaddress
import json
import os
import threading
from pathlib import Path

from .engine import ScanEngine, ScanOptions
from .i18n import _, set_language
from .models import ScanResult
from .profiles import ProfileStore, default_profiles_path
from .store import Store
from .targets import TargetError, check_scope, parse_targets

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
            root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            root.set_border_width(12)
            self.add(root)
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
            self.set_default(self.start_button)
            self.show_all()

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
                    self.store.save_scan(result)
                    GLib.idle_add(self._finished, result, None)
                except Exception as exc:
                    GLib.idle_add(self._finished, None, str(exc))

            threading.Thread(target=work, daemon=True).start()

        def _set_progress(self, step, fraction):
            self.status.set_text(step)
            self.progress.set_fraction(fraction)
            return False

        def cancel_scan(self, *_):
            self.cancel_button.set_sensitive(False)
            if self.engine:
                threading.Thread(target=self.engine.cancel, daemon=True).start()

        def _finished(self, result, error):
            self.start_button.set_sensitive(True)
            self.cancel_button.set_sensitive(False)
            self.progress.set_fraction(0)
            if error:
                self.status.set_text(_("Scan failed") + ": " + error)
                return False
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
            self.status.set_text((_("Scan cancelled") if result.status == "cancelled"
                                  else _("Scan failed") if result.status == "failed"
                                  else _("No hosts found") if not result.hosts
                                  else _("Scan complete")) +
                                 f" · {len(result.hosts)} hosts" +
                                 (" · " + "; ".join(result.warnings) if result.warnings else ""))
            return False

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
