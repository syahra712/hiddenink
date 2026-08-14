"""The conformance harness itself.

A corpus whose author also writes the tool under test needs its own guardrails:
the scoring must not quietly pass a broken tool, and the cases must actually
contain the characters they claim to.
"""

from __future__ import annotations

import pytest

from marklens.audit import (
    CORPUS,
    Tier,
    correctness_cases,
    marklens_adapter,
    policy_cases,
    render,
    run_tool,
)
from marklens.audit.report import _is_invisible_for_display
from marklens.core.clean_text import Profile


class TestCorpusIntegrity:
    def test_case_names_are_unique(self) -> None:
        names = [c.name for c in CORPUS]
        assert len(names) == len(set(names))

    def test_every_case_states_a_reason(self) -> None:
        for case in CORPUS:
            assert case.why.strip(), f"{case.name} has no rationale"

    def test_every_correctness_case_has_a_group(self) -> None:
        for case in correctness_cases():
            assert case.group in {"contraband", "load-bearing", "fidelity"}, case.name

    def test_contraband_cases_actually_change_the_text(self) -> None:
        for case in correctness_cases():
            if case.group == "contraband":
                assert case.is_removal, f"{case.name} expects no removal"

    def test_load_bearing_and_fidelity_cases_expect_no_change(self) -> None:
        for case in correctness_cases():
            if case.group in {"load-bearing", "fidelity"}:
                assert not case.is_removal, f"{case.name} expects a change"

    def test_load_bearing_cases_contain_an_invisible_character(self) -> None:
        """Otherwise the case proves nothing about load-bearing handling."""
        for case in correctness_cases():
            if case.group != "load-bearing":
                continue
            assert any(_is_invisible_for_display(ord(ch)) for ch in case.given), (
                f"{case.name} has no invisible character to preserve"
            )

    def test_both_tiers_are_populated(self) -> None:
        assert len(correctness_cases()) >= 30
        assert len(policy_cases()) >= 5


class TestScoring:
    def test_marklens_passes_every_correctness_case(self) -> None:
        result = run_tool("marklens", marklens_adapter(), correctness_cases())
        passed, total = result.correctness
        failures = [o.case.name for o in result.outcomes if not o.passed]
        assert passed == total, f"regressed on: {failures}"

    def test_scoring_catches_a_tool_that_removes_everything(self) -> None:
        """A destructive tool must score badly, not trivially pass."""

        def destroy(text: str) -> str:
            return "".join(ch for ch in text if ch.isascii() and ch.isprintable())

        result = run_tool("destroyer", destroy, correctness_cases())
        passed, total = result.correctness
        assert passed < total
        assert result.corruptions, "corrupting every emoji must be reported"

    def test_scoring_catches_a_tool_that_does_nothing(self) -> None:
        result = run_tool("noop", lambda t: t, correctness_cases())
        assert result.leaks, "leaving every mark in place must be reported"
        assert not result.corruptions, "a no-op corrupts nothing"

    def test_a_crashing_tool_fails_its_case_without_aborting_the_run(self) -> None:
        def flaky(text: str) -> str:
            if "\U0001f468" in text:
                raise RuntimeError("boom")
            return text

        result = run_tool("flaky", flaky, correctness_cases())
        assert len(result.outcomes) == len(correctness_cases())
        assert any(o.error for o in result.outcomes)

    def test_trailing_newline_is_not_scored_as_a_difference(self) -> None:
        """Tools differ on whether stdout ends with a newline; that is not a defect."""
        result = run_tool("newliner", lambda t: t + "\n", correctness_cases())
        noop = run_tool("noop", lambda t: t, correctness_cases())
        assert result.correctness == noop.correctness

    @pytest.mark.parametrize("profile", list(Profile))
    def test_no_profile_corrupts_load_bearing_content(self, profile: Profile) -> None:
        result = run_tool(profile.value, marklens_adapter(profile), correctness_cases())
        assert not result.corruptions, [o.case.name for o in result.corruptions]


class TestRender:
    def test_output_is_markdown_with_a_summary(self) -> None:
        results = [run_tool("marklens", marklens_adapter())]
        text = render(results)
        assert text.startswith("# Conformance results")
        assert "| tool | correctness |" in text
        assert "marklens" in text

    def test_invisible_characters_are_escaped_not_printed(self) -> None:
        text = render([run_tool("marklens", marklens_adapter())])
        for codepoint in ("​", "‮", "", "\U000e0041"):
            assert codepoint not in text, f"{codepoint!r} leaked into the report raw"

    def test_report_is_deterministic(self) -> None:
        """It is committed to RESULTS.md, so it has to diff cleanly."""
        first = render([run_tool("marklens", marklens_adapter())])
        second = render([run_tool("marklens", marklens_adapter())])
        assert first == second

    def test_policy_cases_are_shown_but_not_scored(self) -> None:
        results = [run_tool("marklens", marklens_adapter())]
        text = render(results)
        assert "not scored" in text
        passed, total = results[0].correctness
        assert total == len(correctness_cases())
        assert all(o.case.tier is Tier.CORRECTNESS for o in results[0].outcomes
                   if o.case.tier is Tier.CORRECTNESS)
