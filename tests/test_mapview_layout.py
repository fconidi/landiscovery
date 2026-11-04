from landiscovery.mapview import TITLE, layout
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
