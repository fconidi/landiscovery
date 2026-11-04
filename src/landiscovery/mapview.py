"""Deterministic topology layout and interactive Cairo view."""
from __future__ import annotations

import math

from .models import Topology

TITLE = "Inferred topology"


def layout_labels(topology: Topology, positions: dict[str, tuple[float, float]],
                  width: float, height: float) -> dict[str, tuple[float, float]]:
    """Place labels outside nodes and separate nearby labels on each side."""
    sides = {"left": [], "right": []}
    for node in topology.nodes:
        if node.id not in positions:
            continue
        x, y = positions[node.id]
        side = "left" if x < width / 2 else "right"
        sides[side].append((node, x, y))
    labels = {}
    for side, items in sides.items():
        items.sort(key=lambda item: (item[2], item[0].id))
        baselines = []
        for _, _, y in items:
            baselines.append(max(60.0, y + 4, baselines[-1] + 18 if baselines else 60.0))
        if baselines and baselines[-1] > height - 16:
            shift = baselines[-1] - (height - 16)
            baselines = [baseline - shift for baseline in baselines]
        for (node, x, _), baseline in zip(items, baselines):
            text_width = min(42, len(node.label)) * 7.5
            left = x - text_width - 16 if side == "left" else x + 16
            left = max(8.0, min(left, width - text_width - 8))
            labels[node.id] = (left, baseline)
    return labels


def layout(topology: Topology, width: float, height: float) -> dict[str, tuple[float, float]]:
    ids = [node.id for node in topology.nodes]
    if not ids:
        return {}
    width, height = max(1.0, width), max(1.0, height)
    if len(ids) == 1:
        return {ids[0]: (width / 2, height / 2)}
    radius = min(width, height) * .37
    positions = {node_id: [width / 2 + radius * math.cos(i * 2 * math.pi / len(ids)),
                           height / 2 + radius * math.sin(i * 2 * math.pi / len(ids))]
                 for i, node_id in enumerate(ids)}
    edges = [(edge.a, edge.b) for edge in topology.edges
             if edge.a in positions and edge.b in positions and edge.a != edge.b]
    preferred = min(100.0, min(width, height) / max(2.0, math.sqrt(len(ids))))
    for _ in range(80):
        forces = {node_id: [0.0, 0.0] for node_id in ids}
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                dx = positions[a][0] - positions[b][0]
                dy = positions[a][1] - positions[b][1]
                dist = max(1.0, math.hypot(dx, dy))
                force = min(30.0, preferred * preferred / (dist * dist))
                fx, fy = force * dx / dist, force * dy / dist
                forces[a][0] += fx
                forces[a][1] += fy
                forces[b][0] -= fx
                forces[b][1] -= fy
        for a, b in edges:
            dx = positions[b][0] - positions[a][0]
            dy = positions[b][1] - positions[a][1]
            dist = max(1.0, math.hypot(dx, dy))
            force = .04 * (dist - preferred)
            fx, fy = force * dx / dist, force * dy / dist
            forces[a][0] += fx
            forces[a][1] += fy
            forces[b][0] -= fx
            forces[b][1] -= fy
        for node_id in ids:
            x, y = positions[node_id]
            fx, fy = forces[node_id]
            positions[node_id] = [min(max(24.0, x + fx), max(24.0, width - 24.0)),
                                  min(max(24.0, y + fy), max(24.0, height - 24.0))]
    return {key: tuple(value) for key, value in positions.items()}


try:
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    from gi.repository import Gdk, Gtk
except ImportError:  # layout remains usable on systems without GTK
    Gtk = None


if Gtk is not None:
    class MapView(Gtk.DrawingArea):
        def __init__(self, on_select=None):
            super().__init__()
            self.topology = Topology()
            self.positions = {}
            self.zoom = 1.0
            self.offset = [0.0, 0.0]
            self.dragging = None
            self.panning = None
            self.on_select = on_select
            self.set_size_request(400, 300)
            self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK |
                            Gdk.EventMask.BUTTON_RELEASE_MASK |
                            Gdk.EventMask.POINTER_MOTION_MASK |
                            Gdk.EventMask.SCROLL_MASK)
            self.connect("draw", self._draw)
            self.connect("button-press-event", self._press)
            self.connect("button-release-event", self._release)
            self.connect("motion-notify-event", self._move)
            self.connect("scroll-event", self._scroll)

        def set_topology(self, topology: Topology | None):
            self.topology = topology or Topology()
            self.positions = {}
            self.zoom = 1.0
            self.offset = [0.0, 0.0]
            self.queue_draw()

        def _screen(self, point):
            return (point[0] * self.zoom + self.offset[0],
                    point[1] * self.zoom + self.offset[1])

        def _draw(self, _widget, cr):
            width, height = self.get_allocated_width(), self.get_allocated_height()
            cr.set_source_rgb(.965, .975, .98)
            cr.paint()
            if not self.positions and self.topology.nodes:
                self.positions = layout(self.topology, width, height)
            cr.set_line_width(1.5)
            cr.set_source_rgb(.55, .62, .66)
            for edge in self.topology.edges:
                if edge.a in self.positions and edge.b in self.positions:
                    x1, y1 = self._screen(self.positions[edge.a])
                    x2, y2 = self._screen(self.positions[edge.b])
                    cr.move_to(x1, y1)
                    cr.line_to(x2, y2)
                    cr.stroke()
            colors = {"gateway": (.08, .40, .58), "router": (.1, .59, .51),
                      "host": (.22, .38, .51)}
            for node in self.topology.nodes:
                if node.id not in self.positions:
                    continue
                x, y = self._screen(self.positions[node.id])
                cr.set_source_rgb(*colors.get(node.kind, colors["host"]))
                cr.arc(x, y, 11, 0, 2 * math.pi)
                cr.fill()
            screen_positions = {key: self._screen(point)
                                for key, point in self.positions.items()}
            label_positions = layout_labels(self.topology, screen_positions, width, height)
            cr.set_source_rgb(.07, .13, .17)
            cr.select_font_face("Sans")
            cr.set_font_size(12)
            for node in self.topology.nodes:
                if node.id in label_positions:
                    cr.move_to(*label_positions[node.id])
                    cr.show_text(node.label[:42])
            cr.set_source_rgb(.07, .13, .17)
            cr.set_font_size(15)
            cr.move_to(16, 25)
            cr.show_text(TITLE)
            cr.set_font_size(11)
            cr.move_to(16, 44)
            cr.show_text("Estimated paths; physical links are not verified")
            return False

        def _hit(self, x, y):
            for node in self.topology.nodes:
                if node.id in self.positions:
                    px, py = self._screen(self.positions[node.id])
                    if math.hypot(x - px, y - py) <= 14:
                        return node.id
            return None

        def _press(self, _widget, event):
            self.dragging = self._hit(event.x, event.y)
            if not self.dragging:
                self.panning = (event.x, event.y)
            if self.dragging and self.on_select:
                self.on_select(self.dragging)
            return bool(self.dragging)

        def _release(self, *_):
            self.dragging = None
            self.panning = None
            return False

        def _move(self, _widget, event):
            if self.dragging:
                self.positions[self.dragging] = ((event.x - self.offset[0]) / self.zoom,
                                                 (event.y - self.offset[1]) / self.zoom)
                self.queue_draw()
                return True
            if self.panning:
                self.offset[0] += event.x - self.panning[0]
                self.offset[1] += event.y - self.panning[1]
                self.panning = (event.x, event.y)
                self.queue_draw()
                return True
            return False

        def _scroll(self, _widget, event):
            scale = 1.1 if event.direction == Gdk.ScrollDirection.UP else 1 / 1.1
            self.zoom = min(3.0, max(.5, self.zoom * scale))
            self.queue_draw()
            return True
