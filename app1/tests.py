from datetime import datetime, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase

from .views import (
    color_assignment_graph,
    dijkstra_distances,
    kmp_contains,
    knapsack_issues,
    lcs_similarity,
    merge_sort_issues,
    prim_minimum_spanning_tree,
)


class AlgorithmTests(SimpleTestCase):
    def test_kmp_search_is_case_insensitive(self):
        self.assertTrue(kmp_contains("Damaged Road", "ROAD"))
        self.assertFalse(kmp_contains("Pothole", "water"))

    def test_lcs_detects_similar_titles(self):
        self.assertGreaterEqual(
            lcs_similarity("Broken street light", "Broken street lights"),
            0.65,
        )

    def test_merge_sort_respects_priority_and_time(self):
        now = datetime.now(timezone.utc)
        issues = [
            SimpleNamespace(priority="low", created_at=now, id=1),
            SimpleNamespace(priority="high", created_at=now, id=2),
        ]
        result = merge_sort_issues(issues)
        self.assertEqual(result[0].priority, "high")

    def test_graph_algorithms(self):
        graph = {
            0: [(1, 2), (2, 5)],
            1: [(0, 2), (2, 1)],
            2: [(0, 5), (1, 1)],
        }
        self.assertEqual(dijkstra_distances(graph, 0)[2], 3)
        tree, distance = prim_minimum_spanning_tree([0, 1, 2], graph)
        self.assertEqual(len(tree), 2)
        self.assertEqual(distance, 3)
        colors = color_assignment_graph(graph, [0, 1, 2])
        self.assertNotEqual(colors[0], colors[1])

    def test_knapsack_stays_within_time_limit(self):
        issues = [
            SimpleNamespace(category="pothole", priority="high"),
            SimpleNamespace(category="garbage", priority="medium"),
        ]
        selected, hours, value = knapsack_issues(issues, 3)
        self.assertEqual(hours, 3)
        self.assertEqual(value, 3)
        self.assertEqual(selected, [issues[0]])
