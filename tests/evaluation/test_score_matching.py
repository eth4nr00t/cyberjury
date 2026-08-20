"""Endpoint and vulnerability category matching tests."""

from evals.score.match import endpoint_match


def test_endpoint_match_tolerates_mount_prefix_and_params():
    assert endpoint_match("GET /api/v1/memories/123/update", "POST /memories/<id>/update") is False
    assert endpoint_match("POST /api/v1/memories/123/update", "POST /memories/<id>/update") is True
    assert endpoint_match("GET /files/abc/content", "GET /files/<id>/content") is True


def test_endpoint_match_does_not_conflate_item_with_collection():
    assert endpoint_match("GET /wallets/<id>", "GET /wallets") is False
    assert endpoint_match("GET /wallets/123", "GET /wallets") is False
    assert endpoint_match("GET /wallets", "GET /wallets") is True


def test_endpoint_match_ignores_a_trailing_handler_annotation():
    assert endpoint_match("POST /v1/user/upsert` (tRPC `user.upsertUser`)`", "POST /v1/user/upsert") is True
    assert endpoint_match("`GET` `/v1/user/detail`", "GET /v1/user/detail") is True
    assert endpoint_match("translate batch handler", "translate batch handler") is True


def test_endpoint_match_ignores_a_query_string():
    assert endpoint_match("GET /api/search/?query=<name>", "GET /api/search/") is True
    assert endpoint_match("GET /api/search/", "GET /api/search/?query=x") is True


def test_endpoint_match_credits_a_report_that_lists_several_routes():
    blob = "GET /files/<id>/content, GET /files/<id>/content/<name>, GET /files/<id>"
    assert endpoint_match(blob, "GET /files/<id>/content") is True
    assert endpoint_match(blob, "DELETE /files/<id>") is False
    assert endpoint_match("GET /a/content POST /a/write", "POST /a/write") is True


def test_category_of_unifies_spaces_and_hyphens():
    from evals.score.match import category_match, category_of

    assert category_of("server-side request forgery") == category_of("server-side-request-forgery")
    assert category_match(category_of("server-side request forgery"), category_of("server-side-request-forgery"))
    assert not category_match(category_of("server-side request forgery"), category_of("cross-site-request-forgery"))


def test_category_of_does_not_maintain_vulnerability_aliases():
    from evals.score.match import category_of

    assert category_of("xxe") == "xxe"
    assert category_of("csrf") == "csrf"
    assert category_of("xml external entity") == "xml-external-entity"


def test_category_match_credits_a_broader_label_but_not_a_sibling():
    from evals.score.match import category_match, category_of

    assert category_match("code-injection", "code-injection")
    assert category_match("injection", "code-injection")
    assert category_match("code-injection", "injection")
    assert not category_match("sql-injection", "code-injection")
    assert not category_match("access-control", "missing-authorization")
    assert not category_match("", "code-injection")
    assert category_of("access control") == "access-control"
    assert category_of("missing access control") == "missing-access-control"


def test_accounting_shape_folds_to_the_accounting_class():
    from evals.score.match import category_match, category_of

    assert not category_match(
        category_of("accounting flaw, one-sided numeric bound"),
        category_of("accounting-precision"),
    )
