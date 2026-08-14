"""Release integrity: the artifact must match the repository.

PyPI renders a project page from the README baked into the uploaded artifact,
and a version can never be re-uploaded. So a README edited after the build
ships stale — which is exactly what happened to 0.1.0: it went out telling
people the package was "not on PyPI yet".

These checks are cheap and run in CI, so the next release cannot repeat it.
"""

from __future__ import annotations

import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import hiddenink

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
README = ROOT / "README.md"

# Every read here passes encoding="utf-8" explicitly. Path.read_text() defaults
# to the platform encoding, which is cp1252 on Windows, and this README contains
# emoji and Devanagari -- so the bare call raises UnicodeDecodeError there. It is
# the same defect that once crashed the CLI on a Windows console, reintroduced in
# the tests that were written to prevent released mistakes. Hence the sweep:
# `grep -rn "read_text()" --include='*.py'` should return nothing.


def _declared_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    assert match, "no version in pyproject.toml"
    return match.group(1)


class TestVersionConsistency:
    def test_package_version_matches_pyproject(self) -> None:
        assert hiddenink.__version__ == _declared_version()

    def test_changelog_mentions_the_current_version(self) -> None:
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        version = _declared_version()
        assert version in changelog, f"CHANGELOG.md has no entry for {version}"


class TestReadmeHonesty:
    """The README is the project page. Claims in it have to be true on release."""

    def test_no_stale_prepublication_language(self) -> None:
        text = README.read_text(encoding="utf-8").lower()
        for phrase in ("not on pypi yet", "not yet published", "coming soon"):
            assert phrase not in text, (
                f"README still says {phrase!r} -- it is published. This exact "
                "mistake shipped in 0.1.0."
            )

    def test_install_instruction_is_the_published_one(self) -> None:
        assert "pip install hiddenink" in README.read_text(encoding="utf-8")

    def test_no_unbalanced_markdown_tables(self) -> None:
        """A ragged table renders as garbage on PyPI, where nobody proofreads it.

        Blocks are tracked by contiguity over *all* lines. Filtering to table
        rows first would merge every table in the file into one block and then
        compare unrelated tables against each other.

        Cells are counted as delimiters minus one, not by splitting the
        pipe-stripped string, so a leading empty cell (``| | a | b |``) counts
        the same way the separator row does.
        """
        expected: int | None = None
        block = 0
        lines = README.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            is_row = stripped.startswith("|") and stripped.endswith("|")
            if not is_row:
                expected = None
                continue
            cells = stripped.count("|") - 1
            if expected is None:
                expected, block = cells, block + 1
            assert cells == expected, (
                f"README.md line {number}: table {block} has a row with {cells} "
                f"cells, expected {expected}: {stripped[:70]}"
            )


@pytest.mark.skipif(
    not (ROOT / "dist").is_dir(), reason="no dist/ built; run python -m build first"
)
class TestBuiltArtifact:
    """When dist/ exists, what is in it must match the working tree."""

    def _wheel(self) -> Path:
        wheels = sorted((ROOT / "dist").glob("*.whl"))
        if not wheels:
            pytest.skip("no wheel in dist/")
        return wheels[-1]

    def test_wheel_is_for_the_declared_version(self) -> None:
        assert f"-{_declared_version()}-" in self._wheel().name

    def test_wheel_readme_matches_the_repository(self) -> None:
        """The check that would have caught the 0.1.0 mistake."""
        with zipfile.ZipFile(self._wheel()) as archive:
            name = next(
                n for n in archive.namelist() if n.endswith(".dist-info/METADATA")
            )
            metadata = archive.read(name).decode("utf-8")
        body = metadata.split("\n\n", 1)[1]
        repo_readme = README.read_text(encoding="utf-8")
        assert body.strip() == repo_readme.strip(), (
            "the README inside the wheel differs from README.md -- rebuild "
            "before uploading, or PyPI will render the stale one forever"
        )

    def test_twine_check_passes(self) -> None:
        artifacts = [str(p) for p in (ROOT / "dist").iterdir()]
        result = subprocess.run(
            [sys.executable, "-m", "twine", "check", *artifacts],
            capture_output=True,
            text=True,
        )
        unusable = ("No module named twine", "ImportError", "cannot import name")
        if result.returncode != 0 and any(s in result.stderr for s in unusable):
            pytest.skip(f"local twine is not runnable: {result.stderr.strip()[-80:]}")
        assert result.returncode == 0, result.stdout + result.stderr
