"""Deterministic maximum weight one to one assignment."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class _FlowEdge:
    to: int
    reverse: int
    capacity: int
    cost: int


def _add_edge(graph: list[list[_FlowEdge]], source: int, target: int, cost: int) -> _FlowEdge:
    forward = _FlowEdge(target, len(graph[target]), 1, cost)
    reverse = _FlowEdge(source, len(graph[source]), 0, -cost)
    graph[source].append(forward)
    graph[target].append(reverse)
    return forward


def _augment_shortest_path(graph: list[list[_FlowEdge]], source: int, sink: int) -> bool:
    distances: list[int | None] = [None] * len(graph)
    previous: list[tuple[int, int] | None] = [None] * len(graph)
    distances[source] = 0
    for _ in range(len(graph) - 1):
        changed = False
        for node, edges in enumerate(graph):
            distance = distances[node]
            if distance is None:
                continue
            for edge_index, edge in enumerate(edges):
                candidate = distance + edge.cost
                if edge.capacity and (distances[edge.to] is None or candidate < distances[edge.to]):
                    distances[edge.to] = candidate
                    previous[edge.to] = (node, edge_index)
                    changed = True
        if not changed:
            break
    if previous[sink] is None:
        return False
    node = sink
    while node != source:
        prior = previous[node]
        if prior is None:
            raise RuntimeError("incomplete score matching path")
        previous_node, edge_index = prior
        edge = graph[previous_node][edge_index]
        edge.capacity = 0
        graph[node][edge.reverse].capacity = 1
        node = previous_node
    return True


def maximum_weight_assignment(weights: Sequence[Sequence[int]]) -> dict[int, int]:
    """Match the most rows, then maximize the sum of positive edge weights."""
    row_count = len(weights)
    column_count = len(weights[0]) if weights else 0
    if any(len(row) != column_count for row in weights):
        raise ValueError("assignment weights must form a rectangular matrix")

    source = 0
    row_start = 1
    column_start = row_start + row_count
    sink = column_start + column_count
    graph: list[list[_FlowEdge]] = [[] for _ in range(sink + 1)]
    assignment_edges: dict[tuple[int, int], _FlowEdge] = {}

    for row_index, row in enumerate(weights):
        row_node = row_start + row_index
        _add_edge(graph, source, row_node, 0)
        for column_index, weight in enumerate(row):
            if weight <= 0:
                continue
            edge = _add_edge(graph, row_node, column_start + column_index, -weight)
            assignment_edges[(row_index, column_index)] = edge
    for column_index in range(column_count):
        _add_edge(graph, column_start + column_index, sink, 0)

    while _augment_shortest_path(graph, source, sink):
        pass

    return {
        row_index: column_index for (row_index, column_index), edge in assignment_edges.items() if edge.capacity == 0
    }
