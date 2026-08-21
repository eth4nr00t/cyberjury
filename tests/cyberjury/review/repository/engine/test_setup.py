"""Repository run unit artifact setup tests."""


def test_seed_run_units_seeds_split_units_and_prunes_orphan(tmp_path):
    from cyberjury.profiles.registry import default_profile
    from cyberjury.review.repository.context import Unit
    from cyberjury.review.repository.engine import _seed_run_units
    from cyberjury.review.repository.scaffold import unit_slug

    (tmp_path / "units").mkdir()
    (tmp_path / "units" / "foo.md").write_text("# Unit: foo.py\n- Status: open\n", encoding="utf-8")
    units = [
        Unit(name="foo.py#1", root=str(tmp_path), files=("foo.py",)),
        Unit(name="foo.py#2", root=str(tmp_path), files=("foo.py",)),
    ]
    _seed_run_units(tmp_path, units, default_profile().paths)
    got = {p.name for p in (tmp_path / "units").glob("*.md")}
    assert got == {f"{unit_slug('foo.py#1')}.md", f"{unit_slug('foo.py#2')}.md"}
