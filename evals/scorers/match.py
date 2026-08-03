"""Matching: turn an endpoint or a category string into a normal form and decide whether
two of them refer to the same thing.

These are pure string functions with no schema dependency, so the schema can build a
normalized Report on top of them without a cycle. Endpoint matching is the strong signal,
method and path after normalization, with a mount prefix tolerated and path params
collapsed to a wildcard. Category matching is the soft fallback for a class an endpoint
does not anchor.
"""

from __future__ import annotations

import re

# loose map from a freeform category or type string to a ledger category, a soft signal
_CATEGORY_HINTS = {
    "insecure-direct-object-reference": ("idor", "direct object", "insecure-direct"),
    "missing-authorization": ("missing auth", "authorization", "authz", "access control", "broken access"),
    "replay-attack": ("replay",),
    "mass-assignment": ("mass assignment", "mass-assignment"),
    "auth-bypass": ("auth bypass", "authentication bypass"),
    # the accounting and math class, a report may name it "rounding" or "accounting" where the
    # key names the class, so fold the synonym to the class
    "accounting-precision": ("accounting", "rounding"),
    # pure abbreviations of one class, a report names the short form and a key the long one
    "xml-external-entity": ("xxe", "xml external entity"),
    "cross-site-request-forgery": ("csrf", "cross-site request forgery", "cross site request forgery"),
}

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def normalize_endpoint(text: str) -> str:
    """Normalize an endpoint so GET /wallets/<wallet_id> and get /wallets/{id} match. All
    backticks are dropped, not only the outer ones, since a report often fences the method
    and the path separately, as in `GET` `/x`. A trailing parenthetical annotation such as
    `tRPC user.upsertUser` in parentheses is removed, so a Source line that names the handler after the
    endpoint still matches the bare endpoint a key entry cites. Free-text non-HTTP sources
    carry no parentheses, so they are left intact. A query string is not part of the endpoint
    identity, so `GET /api/search/?query=x` and `GET /api/search/` are one endpoint."""
    text = text.strip().lower().replace("`", "")
    text = re.sub(r"\?\S*", "", text)
    text = re.sub(r"\([^)]*\)", " ", text)
    text = re.sub(r"[<{][^>}]*[>}]", "*", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _split_endpoint(text: str) -> tuple[str, list[str]]:
    """Split a normalized endpoint into a method and its path segments."""
    parts = normalize_endpoint(text).split(" ", 1)
    if len(parts) == 2 and parts[0] in _METHODS:
        method, path = parts[0], parts[1]
    else:
        method, path = "", parts[-1]
    return method, [s for s in path.strip("/").split("/") if s]


def _report_endpoints(report_ep: str) -> list[str]:
    """Split a report's Source line into the individual routes it names. One defect often
    hits several sibling routes, so a finding lists them together, GET /files/<id>/content,
    GET /files/<id>/content/<file_name>, GET /files/<id>, and a comma or a fresh method token
    starts the next route. A free-text non-HTTP source carries neither, so it stays one
    string. The key entry is always a single endpoint, only the report side lists several."""
    norm = normalize_endpoint(report_ep)
    routes: list[str] = []
    for part in re.split(r"\s*,\s*", norm):
        if not part:
            continue
        # a method token that starts a route, "get /a get /b", begins a new one. It must be
        # followed by whitespace, so a path segment that spells a method, /api/options/x, does
        # not split
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
    """Match by method and path, where either path may carry a leading mount prefix the
    other omits, so a real repository's /api/v1/memories/*/update matches a key entry of
    /memories/*/update. Methods must agree when both are present. The shorter path aligns
    as a suffix of the longer, and the overlap is anchored by its first segment matching as
    a literal or both wildcards, so a deeper item path like /wallets/<id> is not conflated
    with the collection /wallets, the looseness that credited an IDOR report to a safe list
    endpoint. Inside the anchored overlap a path param matches any concrete segment. When the
    report names several routes for one defect, a match on any one of them credits it, since
    they are one finding."""
    return any(_match_one(r, key_entry) for r in _report_endpoints(report_ep))


def category_of(text: str) -> str:
    """The canonical class a free-text category maps to by a soft hint match, else the text
    lowercased with its separators unified, so a report and a key entry naming the same class
    are compared on one form. Spaces and underscores fold to the hyphen the keys use, so a
    report tagged `server-side request forgery` and a key tagged `server-side-request-forgery`
    are one form rather than two."""
    low = text.lower().strip()
    for cat, hints in _CATEGORY_HINTS.items():
        if any(h in low for h in hints):
            return cat
    return re.sub(r"[\s_]+", "-", low).strip("-")


def category_match(report_cat: str, key_cat: str) -> bool:
    """Whether a report's category names the same class as a key entry's. Exact after
    normalization, or one a broader form of the other, so a report tagged the generic
    `injection` still credits a `code-injection` key. The hyphen parts of one are a subset
    of the other's, so `code-injection` and `injection` match, while `code-injection` and
    `sql-injection` do not."""
    if not report_cat or not key_cat:
        return False
    if report_cat == key_cat:
        return True
    a, b = set(report_cat.split("-")), set(key_cat.split("-"))
    return a <= b or b <= a
