from landiscovery.mapview import TITLE, layout, layout_labels
from landiscovery.models import Edge, Node, Topology


def graph(count=4):
    return Topology([Node(str(i), str(i), "host", "10.0.0.0/24")
                     for i in range(count)],
                    [Edge("0", str(i)) for i in range(1, count)])


def test_layout_deterministic():
    assert layout(graph(), 800, 600) == layout(graph(), 800, 600)


def test_layout_positions_inside_bounds():
    assert all(0 <= x <= 800 and 0 <= y <= 600
               for x, y in layout(graph(), 800, 600).values())


def test_layout_single_node():
    assert layout(graph(1), 800, 600) == {"0": (400, 300)}


def test_layout_no_overlap_minimum_distance():
    points = list(layout(graph(5), 800, 600).values())
    assert all((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 >= 20 ** 2
               for i, a in enumerate(points) for b in points[i + 1:])


def test_map_title_marks_topology_inferred():
    assert "Inferred" in TITLE


def test_labels_on_each_side_do_not_overlap():
    topology = graph(15)
    positions = layout(topology, 975, 550)
    labels = layout_labels(topology, positions, 975, 550)
    boxes = []
    for node in topology.nodes:
        x, baseline = labels[node.id]
        boxes.append((x, baseline - 12, x + len(node.label) * 7.5, baseline))
    assert all(a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1]
               for i, a in enumerate(boxes) for b in boxes[i + 1:])
