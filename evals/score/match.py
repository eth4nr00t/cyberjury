"""Match normalized endpoint and category strings.

These functions consume shared normalization and decide whether two strings refer to the
same thing. They have no schema dependency, so report and answer key contracts can use
normalization without creating a cycle.
Endpoint matching is the strong signal, method and path after normalization, with a
mount prefix tolerated and path params collapsed to a wildcard. Category matching is the
soft fallback for a class an endpoint does not anchor.
"""

from __future__ import annotations

import re

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def normalize_endpoint(text: str) -> str:
    """Normalize an endpoint to a stable method and route identity."""
    text = text.strip().lower().replace("`", "")
    text = re.sub(r"\?\S*", "", text)
    text = re.sub(r"\([^)]*\)", " ", text)
    text = re.sub(r"[<{][^>}]*[>}]", "*", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def category_of(text: str) -> str:
    """Normalize category spelling without maintaining a second vulnerability catalog."""
    return re.sub(r"[\s_]+", "-", text.lower().strip()).strip("-")


def _split_endpoint(text: str) -> tuple[str, list[str]]:
    """Split a normalized endpoint into a method and its path segments."""
    parts = normalize_endpoint(text).split(" ", 1)
    if len(parts) == 2 and parts[0] in _METHODS:
        method, path = parts[0], parts[1]
    else:
        method, path = "", parts[-1]
    return method, [s for s in path.strip("/").split("/") if s]


def _report_endpoints(report_ep: str) -> list[str]:
    """Split a report's Source line into the individual routes it names.

    One defect often hits several sibling routes, so a finding lists them together, GET
    /files/<id>/content, GET /files/<id>/content/<file_name>, GET /files/<id>, and a comma
    or a fresh method token starts the next route. A free-text non-HTTP source carries
    neither, so it stays one string. An answer check endpoint is always a single endpoint, only the
    report side lists several.
    """
    norm = normalize_endpoint(report_ep)
    routes: list[str] = []
    for part in re.split(r"\s*,\s*", norm):
        if not part:
            continue
        for piece in re.split(rf"(?=\b(?:{'|'.join(_METHODS)})\b\s)", part):
            piece = piece.strip()
            if piece:
                routes.append(piece)
    return routes or [norm]


def _match_one(report_ep: str, key_entry: str) -> bool:
    rm, rseg = _split_endpoint(report_ep)
    km, kseg = _split_endpoint(key_entry)
    if rm and km and rm != km:
        return False
    if not rseg or not kseg:
        return False
    short, long_ = (rseg, kseg) if len(rseg) <= len(kseg) else (kseg, rseg)
    tail = long_[-len(short) :]
    if not (short[0] == tail[0] or (short[0] == "*" and tail[0] == "*")):
        return False
    return all(a == b or a == "*" or b == "*" for a, b in zip(short, tail, strict=False))


def endpoint_match(report_ep: str, key_entry: str) -> bool:
    """Match by method and path while tolerating leading mount segments.

    A real repository's /api/v1/memories/*/update matches an answer check endpoint of
    /memories/*/update. Methods must agree when both are present. The shorter path aligns as
    a suffix of the longer, and the overlap is anchored by its first segment matching as a
    literal or both wildcards, so a deeper item path like /wallets/<id> is not conflated
    with the collection /wallets, the looseness that credited an IDOR report to a clean check
    endpoint. Inside the anchored overlap a path param matches any concrete segment. When
    the report names several routes for one defect, a match on any one of them credits it,
    since they are one finding.
    """
    return any(_match_one(r, key_entry) for r in _report_endpoints(report_ep))


def category_match(report_cat: str, key_cat: str) -> bool:
    """Whether a report's category names the same class as an answer check's.

    Exact after normalization, or one a broader form of the other, so a report tagged the
    generic `injection` still credits a `code-injection` key. The hyphen parts of one are a
    subset of the other's, so `code-injection` and `injection` match, while `code-injection`
    and `sql-injection` do not.
    """
    report_cat = category_of(report_cat)
    key_cat = category_of(key_cat)
    if not report_cat or not key_cat:
        return False
    if report_cat == key_cat:
        return True
    a, b = set(report_cat.split("-")), set(key_cat.split("-"))
    return a <= b or b <= a
