"""Tests for nfrtop.

    python3 -m unittest -v            # or: python3 test_nfrtop.py
    python3 test_nfrtop.py --update-golden

Standard library only, like the tool itself, so running the tests needs nothing
that running nfrtop does not already need.

Two kinds of test live here. The unit tests pin behavior that was reasoned
about - the parser's invariants, the counter arithmetic, the unit boundaries -
and each one stands on its own. The golden tests below them record what the
renderer currently produces for a fixed ruleset; they prove nothing by
themselves, but they turn any unintended change to a frame into a failure.

The golden pair is deliberately dumb: an `nft -j list ruleset` dump in and plain
text out, with no Python in between. Swapping in a dump from a real firewall is
all it takes to hold this to that firewall - which is what tests/real.json is.
"""

import argparse
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import ClassVar
from unittest import mock

import nfrtop


TESTS = Path(__file__).resolve().parent / "tests"
GOLDEN = TESTS / "golden"
NFRTOP = Path(nfrtop.__file__).resolve()

# The cadence the golden frames were sampled at. The counters in the two
# fixtures differ by round multiples of it, so the rates come out exact.
INTERVAL = 2.0


# --------------------------------------------------------------------------
# helpers


@contextmanager
def terminal_width(columns):
    """Pin the width render_lines() sees.

    shutil.get_terminal_size() prefers COLUMNS over the real terminal, so a
    frame does not depend on the window the tests happen to run in.
    """
    old = os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = str(columns)
    try:
        yield
    finally:
        if old is None:
            del os.environ["COLUMNS"]
        else:
            os.environ["COLUMNS"] = old


@contextmanager
def environment(**values):
    """Set or, for a value of None, unset environment variables."""
    old = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def fixture(name):
    return (TESTS / name).read_text()


def filter_args(**overrides):
    """The subset of the parsed CLI that matches_filters() reads."""
    # min_rate_bps is None where --min-rate went unasked for; 0.0 is a
    # threshold like any other, and one a rule needs a counter to meet.
    args = argparse.Namespace(family=None, table=None, chain=None,
                              counted_only=False, min_rate_bps=None)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def rule_at(ruleset, chain, handle):
    """Pick one rule out of a ruleset.

    nft hands out handles per table, so a handle is not on its own a name for a
    rule. The chain is what settles it - which is half of why Rule.key is more
    than a handle.
    """
    found = [r for r in ruleset.rules
             if r.chain == chain and r.handle == handle]
    assert len(found) == 1, (chain, handle, found)
    return found[0]


def make_rule(**overrides):
    fields = dict(family="inet", table="filter", chain="input", handle=1,
                  packets=0, bytes=0, text="counter accept", order=0)
    fields.update(overrides)
    return nfrtop.Rule(**fields)


def plain(segments):
    """The words of a segment list, with the roles dropped.

    The formatters hand back (text, role) pairs so that the display can tell a
    number from a word nfrtop wrote itself; what most of these tests are asking
    about is the words. The pairs carry their own spacing, so this is a
    concatenation rather than a join.
    """
    return "".join(text for text, _ in segments)


def option_text(fields):
    """The plain reading of what split_rule() left for OPTIONS."""
    return plain(fields["option_parts"])


# --------------------------------------------------------------------------
# number formatting


class TestHumanFormatting(unittest.TestCase):
    def test_missing_values_render_as_a_dash(self):
        for fn in (nfrtop.human_count, nfrtop.human_bytes, nfrtop.human_rate,
                   nfrtop.human_bitrate, nfrtop.human_pps):
            self.assertEqual(fn(None), "-", fn.__name__)

    def test_counts_are_decimal(self):
        self.assertEqual(nfrtop.human_count(0), "0")
        self.assertEqual(nfrtop.human_count(999), "999")
        self.assertEqual(nfrtop.human_count(1000), "1.0K")
        self.assertEqual(nfrtop.human_count(1_500_000), "1.5M")

    def test_count_rounds_up_a_unit_before_the_mantissa_reaches_1000(self):
        self.assertEqual(nfrtop.human_count(999_940), "999.9K")
        self.assertEqual(nfrtop.human_count(999_950), "1.0M")

    def test_count_past_the_last_unit_drops_the_decimal(self):
        self.assertEqual(nfrtop.human_count(10 ** 20), "100000P")

    def test_bytes_are_binary(self):
        self.assertEqual(nfrtop.human_bytes(0), "0B")
        self.assertEqual(nfrtop.human_bytes(1023), "1023B")
        self.assertEqual(nfrtop.human_bytes(1024), "1.0KiB")
        self.assertEqual(nfrtop.human_bytes(65536), "64.0KiB")

    def test_bytes_drop_the_decimal_above_the_display_threshold(self):
        # Between 999.95 and 1023.95 of a unit the mantissa is 4 digits, so the
        # decimal goes to keep the column width predictable.
        self.assertEqual(nfrtop.human_bytes(1010 * 1024), "1010KiB")

    def test_rate_suffixes(self):
        self.assertEqual(nfrtop.human_rate(1024), "1.0KiB/s")
        self.assertEqual(nfrtop.human_bitrate(1000), "8.0Kb/s")

    def test_pps_keeps_a_decimal_while_it_fits(self):
        self.assertEqual(nfrtop.human_pps(0), "0.0")
        self.assertEqual(nfrtop.human_pps(3.25), "3.2")
        self.assertEqual(nfrtop.human_pps(999.9), "999.9")
        self.assertEqual(nfrtop.human_pps(1000), "1.0K")


class TestParseRate(unittest.TestCase):
    def test_plain_number_is_bytes_per_second(self):
        self.assertEqual(nfrtop.parse_rate("200", bits=False), 200.0)

    def test_byte_prefixes_are_binary(self):
        self.assertEqual(nfrtop.parse_rate("1.5k", bits=False), 1536.0)
        self.assertEqual(nfrtop.parse_rate("10M", bits=False), 10 * 1024 ** 2)

    def test_bit_prefixes_are_decimal_and_convert_to_bytes(self):
        self.assertEqual(nfrtop.parse_rate("1.5k", bits=True), 1500 / 8)
        self.assertEqual(nfrtop.parse_rate("100Mibps", bits=True),
                         100 * 1000 ** 2 / 8)

    def test_optional_unit_suffixes_are_accepted(self):
        self.assertEqual(nfrtop.parse_rate("1.5kb/s", bits=False), 1536.0)
        self.assertEqual(nfrtop.parse_rate(" 200 B ", bits=False), 200.0)

    def test_garbage_is_rejected(self):
        for text in ("", "fast", "1.2.3", "10X", "-5"):
            with self.assertRaises(ValueError, msg=text):
                nfrtop.parse_rate(text, bits=False)

    def test_a_rate_too_large_to_hold_is_rejected(self):
        # float() hands back inf rather than raising, and an infinite threshold
        # would hide the whole ruleset while looking like a filter.
        with self.assertRaises(ValueError):
            nfrtop.parse_rate("9" * 400 + "T", bits=False)


# --------------------------------------------------------------------------
# rates


class TestRates(unittest.TestCase):
    def sample(self, name):
        return nfrtop.parse_ruleset(fixture(name))

    def test_rates_across_two_samples(self):
        first = self.sample("sample.json")
        second = self.sample("sample-next.json")
        nfrtop.update_rates(second.rules, {r.key: r for r in first.rules},
                            INTERVAL)
        rule = rule_at(second, "input", 7)
        self.assertEqual(rule.pps, 100.0)       # 1224 - 1024 over 2s
        self.assertEqual(rule.bps, 10000.0)     # 85536 - 65536 over 2s

    def test_first_sighting_of_a_rule_reports_zero(self):
        rule = make_rule(packets=10, bytes=20)
        nfrtop.update_rates([rule], {}, INTERVAL)
        self.assertEqual((rule.pps, rule.bps), (0.0, 0.0))

    def test_counter_reset_reports_zero_rather_than_a_negative_rate(self):
        old = make_rule(packets=100, bytes=1000)
        new = make_rule(packets=1, bytes=10)
        nfrtop.update_rates([new], {old.key: old}, INTERVAL)
        self.assertEqual((new.pps, new.bps), (0.0, 0.0))

    def test_a_reused_handle_does_not_invent_a_rate(self):
        # nft hands the same handle out again after a reload. Subtracting an
        # unrelated rule's counters would fabricate a rate, so the body is part
        # of the identity.
        old = make_rule(handle=7, text="counter accept", packets=1000,
                        bytes=100000)
        new = make_rule(handle=7, text="counter drop", packets=5, bytes=50)
        nfrtop.update_rates([new], {old.key: old}, INTERVAL)
        self.assertNotEqual(old.key, new.key)
        self.assertEqual((new.pps, new.bps), (0.0, 0.0))

    def test_a_rule_without_a_counter_keeps_no_rate(self):
        rule = make_rule(packets=None, bytes=None)
        nfrtop.update_rates([rule], {}, INTERVAL)
        self.assertIsNone(rule.pps)
        self.assertIsNone(rule.bps)

    def test_non_positive_elapsed_is_ignored(self):
        rule = make_rule(packets=10, bytes=20)
        nfrtop.update_rates([rule], {}, 0)
        self.assertIsNone(rule.pps)

    def test_was_active_is_set_by_traffic(self):
        old = make_rule(packets=0, bytes=0)
        new = make_rule(packets=5, bytes=500)
        nfrtop.update_rates([new], {old.key: old}, INTERVAL)
        self.assertTrue(new.was_active)

    def test_was_active_survives_a_quiet_sample(self):
        old = make_rule(packets=5, bytes=500, was_active=True)
        new = make_rule(packets=5, bytes=500)
        nfrtop.update_rates([new], {old.key: old}, INTERVAL)
        self.assertEqual(new.pps, 0.0)
        self.assertTrue(new.was_active)

    def test_a_rule_that_never_matched_is_not_active(self):
        old = make_rule(packets=0, bytes=0)
        new = make_rule(packets=0, bytes=0)
        nfrtop.update_rates([new], {old.key: old}, INTERVAL)
        self.assertFalse(new.was_active)


# --------------------------------------------------------------------------
# filtering and sorting


class TestFilters(unittest.TestCase):
    def setUp(self):
        self.ruleset = nfrtop.parse_ruleset(fixture("sample.json"))

    def kept(self, **overrides):
        args = filter_args(**overrides)
        return [r for r in self.ruleset.rules
                if nfrtop.matches_filters(r, args)]

    def test_no_filter_keeps_everything(self):
        self.assertEqual(len(self.kept()), len(self.ruleset.rules))

    def test_family_table_and_chain_match_exactly(self):
        self.assertTrue(all(r.family == "ip" for r in self.kept(family="ip")))
        self.assertTrue(all(r.table == "nat" for r in self.kept(table="nat")))
        self.assertTrue(all(r.chain == "input"
                            for r in self.kept(chain="input")))
        self.assertEqual(self.kept(chain="inp"), [])   # not a prefix match

    def test_counted_only_drops_rules_without_a_counter(self):
        kept = self.kept(counted_only=True)
        self.assertTrue(all(r.packets is not None for r in kept))
        self.assertLess(len(kept), len(self.ruleset.rules))

    def test_min_rate_hides_rules_that_cannot_report_one(self):
        rule = make_rule(packets=None, bytes=None, bps=None)
        self.assertFalse(
            nfrtop.matches_filters(rule, filter_args(min_rate_bps=1.0))
        )

    def test_min_rate_keeps_a_counted_rule_until_the_first_measurement(self):
        rule = make_rule(packets=10, bytes=20, bps=None)
        self.assertTrue(
            nfrtop.matches_filters(rule, filter_args(min_rate_bps=1000.0))
        )

    def test_a_min_rate_of_zero_is_still_a_filter(self):
        # It asks for rules that can report a rate, which a rule with no
        # counter never can, and 0.0 must not read as --min-rate unasked for.
        counted = make_rule(packets=10, bytes=20, bps=0.0)
        uncounted = make_rule(packets=None, bytes=None, bps=None)
        args = filter_args(min_rate_bps=0.0)
        self.assertTrue(nfrtop.matches_filters(counted, args))
        self.assertFalse(nfrtop.matches_filters(uncounted, args))

    def test_min_rate_compares_once_measured(self):
        slow = make_rule(packets=10, bytes=20, bps=10.0)
        fast = make_rule(packets=10, bytes=20, bps=10000.0)
        args = filter_args(min_rate_bps=1000.0)
        self.assertFalse(nfrtop.matches_filters(slow, args))
        self.assertTrue(nfrtop.matches_filters(fast, args))

    def test_filters_are_combined_with_and(self):
        args = filter_args(family="inet", chain="postrouting")
        self.assertEqual(
            [r for r in self.ruleset.rules if nfrtop.matches_filters(r, args)],
            [],
        )


class TestSorting(unittest.TestCase):
    def rules(self):
        return [
            make_rule(order=0, handle=1, packets=5, bytes=50, bps=1.0),
            make_rule(order=1, handle=2, packets=None, bytes=None, bps=None),
            make_rule(order=2, handle=3, packets=99, bytes=990, bps=100.0),
            make_rule(order=3, handle=4, packets=5, bytes=50, bps=1.0),
        ]

    def order_of(self, mode):
        rules = self.rules()
        nfrtop.sort_rules(rules, mode)
        return [r.handle for r in rules]

    def test_default_is_ruleset_order(self):
        self.assertEqual(self.order_of("rule"), [1, 2, 3, 4])

    def test_rate_sorts_descending(self):
        self.assertEqual(self.order_of("rate"), [3, 1, 4, 2])

    def test_packets_and_bytes_sort_descending(self):
        self.assertEqual(self.order_of("packets"), [3, 1, 4, 2])
        self.assertEqual(self.order_of("bytes"), [3, 1, 4, 2])

    def test_rules_without_a_value_fall_to_the_end(self):
        self.assertEqual(self.order_of("rate")[-1], 2)

    def test_ties_keep_ruleset_order(self):
        self.assertEqual(self.order_of("rate")[1:3], [1, 4])


# --------------------------------------------------------------------------
# layout


class TestTruncate(unittest.TestCase):
    def test_short_enough_is_untouched(self):
        self.assertEqual(nfrtop.truncate("eth0", 8), "eth0")

    def test_exact_fit_is_untouched(self):
        self.assertEqual(nfrtop.truncate("eth0", 4), "eth0")

    def test_overflow_ends_in_an_ellipsis(self):
        self.assertEqual(nfrtop.truncate("eth0", 3), "et…")

    def test_degenerate_widths(self):
        self.assertEqual(nfrtop.truncate("eth0", 1), "…")
        self.assertEqual(nfrtop.truncate("eth0", 0), "")
        self.assertEqual(nfrtop.truncate("eth0", -1), "")

    def test_a_wide_character_is_counted_as_the_two_cells_it_takes(self):
        # Four characters, eight cells: cut by length it would sit four cells
        # past the edge of its column.
        self.assertEqual(nfrtop.display_width("日本語の"), 8)
        self.assertEqual(nfrtop.truncate("日本語の", 8), "日本語の")
        self.assertEqual(nfrtop.truncate("日本語の", 5), "日本…")

    def test_a_wide_character_is_not_split_to_reach_the_ellipsis(self):
        # Room for two cells before the mark, so the second character cannot
        # go in and the cell is left one short rather than one over.
        self.assertEqual(nfrtop.truncate("日本語", 4), "日…")

    def test_a_combining_mark_takes_no_cell_of_its_own(self):
        self.assertEqual(nfrtop.display_width("éth0"), 4)


class TestTruncateSegments(unittest.TestCase):
    """OPTIONS is cut in pieces so that it can be colored in pieces.

    The pieces must land exactly where the whole string would have, or a color
    would be moving a column edge.
    """

    CASES = (
        [("tcp dport", None), (" ", None), ("22", nfrtop.GREEN),
         (" ", None), ("/* web */", nfrtop.FAINT)],
        [("IN", nfrtop.FAINT), (" ", None), ("lo", None),
         (" ", None), ("ct state { new }", None)],
        # A wide character at the cut is what tells a walk over the segments
        # apart from one over the joined-up string: it can leave a cell free
        # that the segment after would otherwise be let into.
        [("日本語", None), (" ", None), ("eth0", None),
         (" ", None), ("/* 通信 */", nfrtop.FAINT)],
        # A combining mark measures zero, so it fits in a width of zero on the
        # way in and has to be turned away on the size of the column instead.
        [("é", None), ("́", nfrtop.FAINT), ("lo", None)],
    )

    def cut(self, segments, width):
        return plain(nfrtop.truncate_segments(segments, width))

    def test_the_plain_text_is_what_truncate_would_have_produced(self):
        for segments in self.CASES:
            joined = plain(segments)
            for width in range(-1, 40):
                with self.subTest(text=joined, width=width):
                    self.assertEqual(self.cut(segments, width),
                                     nfrtop.truncate(joined, width))

    def test_a_column_of_no_cells_holds_nothing_that_measures_zero_either(self):
        # Costing nothing to draw is not the same as being there to draw: a
        # combining mark passes a width check made on cells alone, so the
        # width has to be turned away before the measuring starts.
        self.assertEqual(self.cut([("́", None)], 0), "")

    def test_an_empty_segment_is_dropped_rather_than_measured(self):
        self.assertEqual(self.cut([("", nfrtop.FAINT), ("lo", None)], 40), "lo")

    def test_a_segment_keeps_its_color_through_the_cut(self):
        self.assertEqual(
            nfrtop.truncate_segments([("IN", nfrtop.FAINT), (" ", None),
                                      ("lo", None)], 40),
            [("IN", nfrtop.FAINT), (" ", None), ("lo", None)])

    def test_the_ellipsis_is_the_frames_word_rather_than_the_rulesets(self):
        parts = nfrtop.truncate_segments([("blocklist", nfrtop.FAINT)], 5)
        self.assertEqual(parts[-1], (nfrtop.ELLIPSIS, None))

    def test_an_escape_is_spelled_out_before_any_color_is_added(self):
        # A color code mixed into the text before truncate() would be escaped
        # by it and printed, so the escaping happens here, on the text alone.
        self.assertEqual(
            nfrtop.truncate_segments([("\x1b[2J", nfrtop.FAINT)], 40),
            [("\\x1b[2J", nfrtop.FAINT)])


@contextmanager
def encoding(name):
    """Pretend stdout is a codec that cannot carry everything, or one that can."""
    previous = nfrtop.ENCODING
    nfrtop.ENCODING = nfrtop.limited_encoding(
        io.TextIOWrapper(io.BytesIO(), encoding=name))
    try:
        yield
    finally:
        nfrtop.ENCODING = previous


class TestSafe(unittest.TestCase):
    """What the ruleset says must not be something the terminal obeys."""

    def test_an_escape_in_a_comment_is_spelled_out(self):
        self.assertEqual(nfrtop.safe("a\x1b[2Jb"), "a\\x1b[2Jb")

    def test_a_newline_cannot_put_one_rule_on_two_lines(self):
        self.assertEqual(nfrtop.safe("a\nb\rc\td"),
                         "a\\x0ab\\x0dc\\x09d")

    def test_a_bidi_override_cannot_reorder_a_cell(self):
        self.assertEqual(nfrtop.safe("a‮b"), "a\\u202eb")

    def test_ordinary_text_including_wide_characters_is_left_alone(self):
        for text in ("tcp dport 22", "日本語", "eth0", "@blocklist"):
            self.assertEqual(nfrtop.safe(text), text)

    def test_truncate_is_where_it_happens_so_nothing_can_skip_it(self):
        self.assertEqual(nfrtop.truncate("\x1b[2J", 40), "\\x1b[2J")

    def test_what_stdout_cannot_carry_is_escaped_before_it_is_measured(self):
        # Written straight out, the codec would turn it into an escape after
        # every column had been sized for the character it used to be.
        with encoding("ascii"):
            self.assertEqual(nfrtop.safe("日"), "\\u65e5")
            self.assertEqual(nfrtop.display_width(nfrtop.safe("日")), 6)

    def test_a_utf_stdout_is_asked_nothing_per_character(self):
        with encoding("utf-8"):
            self.assertEqual(nfrtop.safe("日本語"), "日本語")

    def test_limited_encoding_names_only_a_codec_that_cannot_carry_all(self):
        for name, expected in (("utf-8", None), ("utf-16", None),
                               ("ascii", "ascii"), ("latin-1", "latin-1")):
            with self.subTest(encoding=name):
                stream = io.TextIOWrapper(io.BytesIO(), encoding=name)
                self.assertEqual(nfrtop.limited_encoding(stream), expected)

    def test_a_stream_that_will_not_say_is_assumed_to_carry_least(self):
        # Same assumption usable_ellipsis() makes, and in the same direction:
        # escaping something that would have been fine costs a cell, and not
        # escaping something that would not costs the layout.
        self.assertEqual(nfrtop.limited_encoding(io.StringIO()), "ascii")


class TestPad(unittest.TestCase):
    def test_padding_counts_cells_and_not_characters(self):
        self.assertEqual(nfrtop.pad("日本", 6, "<"), "日本  ")
        self.assertEqual(nfrtop.pad("日本", 6, ">"), "  日本")

    def test_nothing_is_added_to_something_already_wide_enough(self):
        self.assertEqual(nfrtop.pad("eth0", 4, "<"), "eth0")
        self.assertEqual(nfrtop.pad("eth0", 2, "<"), "eth0")


class TestUsableEllipsis(unittest.TestCase):
    """The mark is one column wide either way, so only encodability decides."""

    class Stream:
        def __init__(self, encoding):
            self.encoding = encoding

    def encoding(self, name):
        return self.Stream(name)

    def test_utf8_keeps_the_ellipsis(self):
        self.assertEqual(nfrtop.usable_ellipsis(self.encoding("utf-8")), "…")

    def test_ascii_falls_back_to_a_dot(self):
        self.assertEqual(nfrtop.usable_ellipsis(self.encoding("ascii")), ".")

    def test_a_stream_that_names_no_encoding_is_treated_as_ascii(self):
        self.assertEqual(nfrtop.usable_ellipsis(self.encoding(None)), ".")

    def test_an_encoding_python_does_not_know_is_treated_as_ascii(self):
        self.assertEqual(nfrtop.usable_ellipsis(self.encoding("nonesuch")), ".")


class TestRstripRow(unittest.TestCase):
    def test_plain_padding_goes(self):
        self.assertEqual(nfrtop.rstrip_row("abc   "), "abc")

    def test_padding_tucked_inside_a_color_run_goes_too(self):
        row = f"{nfrtop.GREEN}abc   {nfrtop.RESET}"
        self.assertEqual(row.rstrip(), row)     # plain rstrip cannot help
        self.assertEqual(nfrtop.rstrip_row(row),
                         f"{nfrtop.GREEN}abc{nfrtop.RESET}")


class TestLayout(unittest.TestCase):
    def setUp(self):
        self.rules = nfrtop.parse_ruleset(fixture("sample.json")).rules

    def columns(self, width, grouped=True):
        view = nfrtop.View(grouped=grouped, bits=False, color=False)
        columns, options_width, _ = nfrtop.layout(self.rules, width, view)
        return {c.title: c for c in columns}, options_width

    def test_flat_adds_the_location_columns(self):
        grouped, _ = self.columns(200)
        flat, _ = self.columns(200, grouped=False)
        self.assertNotIn("FAM", grouped)
        self.assertEqual(list(flat)[:2], ["FAM", "CHAIN"])

    def test_counter_columns_keep_their_width_whatever_is_on_screen(self):
        # Otherwise the table shifts sideways when a counter crosses a unit.
        wide, _ = self.columns(200)
        for title in ("PKTS", "BYTES", "PPS", "RATE"):
            fixed = [c for c in nfrtop.base_columns(False) if c.title == title]
            self.assertEqual(wide[title].width, fixed[0].prefw, title)

    def test_a_content_sized_column_shrinks_to_its_values(self):
        columns, _ = self.columns(200)
        # No handle in the fixture is wider than 2 digits, so HNDL sits at its
        # floor rather than at its preferred width.
        self.assertEqual(columns["HNDL"].width, 4)

    def test_a_column_never_shrinks_below_its_floor(self):
        columns, _ = self.columns(40)
        for title, column in columns.items():
            self.assertGreaterEqual(column.width, column.minw, title)
            self.assertGreaterEqual(column.width, len(title), title)

    def test_a_narrow_terminal_drops_columns_rather_than_wrap(self):
        # Shrinking stops at the floors, and what is left over has to come out
        # of the set of columns itself.
        wide, _ = self.columns(200)
        narrow, options_width = self.columns(40)
        self.assertLess(len(narrow), len(wide))
        self.assertGreater(options_width, 0)
        used = sum(c.width + 1 for c in narrow.values())
        self.assertLessEqual(used + options_width, 40)

    def test_the_columns_that_name_a_rule_are_never_dropped(self):
        for width in (200, 100, 60, 40, 20, 10):
            grouped, _ = self.columns(width)
            self.assertIn("NUM", grouped, width)
            self.assertIn("TARGET", grouped, width)
            flat, _ = self.columns(width, grouped=False)
            self.assertIn("FAM", flat, width)
            self.assertIn("CHAIN", flat, width)

    def test_narrow_terminals_give_options_away_first(self):
        _, wide = self.columns(200)
        _, narrow = self.columns(100)
        self.assertGreater(wide, narrow)

    def test_widest_slack_is_taken_first(self):
        roomy, _ = self.columns(200)
        tight, _ = self.columns(110)
        # SOURCE carries the most slack over its floor, so it gives first.
        self.assertLess(tight["SOURCE"].width, roomy["SOURCE"].width)
        self.assertEqual(tight["NUM"].width, roomy["NUM"].width)


# --------------------------------------------------------------------------
# color selection


class TestWantColor(unittest.TestCase):
    def test_explicit_modes_win(self):
        with environment(NO_COLOR="1"):
            self.assertTrue(nfrtop.want_color("always"))
        with environment(NO_COLOR=None):
            self.assertFalse(nfrtop.want_color("never"))

    def test_no_color_is_honored_in_auto(self):
        with environment(NO_COLOR="1"):
            self.assertFalse(nfrtop.want_color("auto"))

    def test_auto_is_off_when_stdout_is_not_a_terminal(self):
        with environment(NO_COLOR=None), redirect_stdout(io.StringIO()):
            self.assertFalse(nfrtop.want_color("auto"))


class TestPaint(unittest.TestCase):
    def test_color_off_returns_the_text_unchanged(self):
        self.assertEqual(nfrtop.paint("x", nfrtop.GREEN, False), "x")

    def test_no_code_returns_the_text_unchanged(self):
        self.assertEqual(nfrtop.paint("x", None, True), "x")

    def test_a_painted_cell_always_closes_with_reset(self):
        self.assertEqual(nfrtop.paint("x", nfrtop.GREEN, True),
                         f"{nfrtop.GREEN}x{nfrtop.RESET}")

    def test_direction_follows_the_hook(self):
        self.assertEqual(nfrtop.direction_color("input"), nfrtop.GREEN)
        self.assertEqual(nfrtop.direction_color("postrouting"), nfrtop.RED)
        self.assertEqual(nfrtop.direction_color("forward"), nfrtop.YELLOW)
        self.assertIsNone(nfrtop.direction_color(""))

    def test_a_quiet_rule_that_once_carried_traffic_keeps_its_foreground(self):
        style = nfrtop.directional(lambda r: r.pps)
        never = make_rule(pps=0.0, hook="input", was_active=False)
        quiet = make_rule(pps=0.0, hook="input", was_active=True)
        busy = make_rule(pps=5.0, hook="input", was_active=True)
        self.assertEqual(style(never), nfrtop.FAINT)
        self.assertIsNone(style(quiet))
        self.assertEqual(style(busy), nfrtop.GREEN)

    def test_a_jump_destination_is_not_a_verdict_color(self):
        self.assertEqual(nfrtop.target_color(make_rule(target="DROP")),
                         nfrtop.RED)
        self.assertIsNone(nfrtop.target_color(make_rule(target="wan")))
        self.assertEqual(nfrtop.target_color(make_rule(target="")),
                         nfrtop.FAINT)


# --------------------------------------------------------------------------
# frame writing - the flicker-free redraw


class CountingStream(io.StringIO):
    """A stdout that remembers how many write() calls reached it."""

    def __init__(self):
        super().__init__()
        self.writes = 0

    def write(self, text):
        self.writes += 1
        return super().write(text)


class TestWriteFrame(unittest.TestCase):
    # One frame, reused by every test here: the blank line in the
    # middle is what proves the erases are written even where there is
    # nothing to erase behind.
    LINES: ClassVar[list] = ["alpha", "", "beta"]

    def capture(self, live):
        stream = CountingStream()
        with redirect_stdout(stream):
            nfrtop.write_frame(self.LINES, live=live)
        return stream

    def test_a_frame_leaves_in_a_single_write(self):
        # Written line by line, a terminal repaints line by line and the fill
        # is visible.
        self.assertEqual(self.capture(live=True).writes, 1)

    def test_a_live_frame_never_blanks_the_screen(self):
        out = self.capture(live=True).getvalue()
        self.assertNotIn("\033[2J", out)

    def test_a_live_frame_homes_and_overwrites(self):
        out = self.capture(live=True).getvalue()
        self.assertTrue(out.startswith(nfrtop.SYNC_BEGIN + nfrtop.HOME), out)
        self.assertTrue(out.endswith(nfrtop.CLEAR_EOS + nfrtop.SYNC_END), out)

    def test_every_line_erases_to_the_end_of_its_row(self):
        out = self.capture(live=True).getvalue()
        self.assertEqual(out.count(nfrtop.CLEAR_EOL), len(self.LINES))
        for line in self.LINES:
            self.assertIn(line + nfrtop.CLEAR_EOL, out)

    def test_the_synchronised_update_is_balanced(self):
        out = self.capture(live=True).getvalue()
        self.assertEqual(out.count(nfrtop.SYNC_BEGIN), 1)
        self.assertEqual(out.count(nfrtop.SYNC_END), 1)

    def test_a_non_live_frame_is_plain_text(self):
        out = self.capture(live=False).getvalue()
        self.assertEqual(out, "alpha\n\nbeta\n")
        self.assertNotIn("\033", out)

    def test_a_written_frame_ends_with_a_newline(self):
        self.assertTrue(self.capture(live=False).getvalue().endswith("\n"))

    def test_a_live_frame_does_not_end_with_a_newline(self):
        # A frame exactly as tall as the terminal would scroll on that last
        # newline, and scrolling takes the header off the top of the screen.
        out = self.capture(live=True).getvalue()
        body = out[:-len(nfrtop.CLEAR_EOS + nfrtop.SYNC_END)]
        self.assertFalse(body.endswith("\n"), out)
        self.assertEqual(body.count("\n"), len(self.LINES) - 1)


class TestRenderLines(unittest.TestCase):
    def setUp(self):
        self.ruleset = nfrtop.parse_ruleset(fixture("sample.json"))

    def render(self, width=100, grouped=True, bits=False, color=False,
               interval=INTERVAL, hidden=0, height=None):
        view = nfrtop.View(grouped=grouped, bits=bits, color=color)
        with terminal_width(width):
            return nfrtop.render_lines(self.ruleset.rules, self.ruleset.chains,
                                       view, interval, hidden, height)

    def test_no_line_is_wider_than_the_terminal(self):
        for width in (200, 100, 60, 40, 20, 10):
            for line in self.render(width=width):
                self.assertLessEqual(nfrtop.display_width(line), width,
                                     f"{width}: {line!r}")

    def test_a_dropped_column_hands_its_matches_back_to_options(self):
        # The match a column lifted is not repeated in OPTIONS, so dropping the
        # column would take the match off the screen with it.
        wide = self.render(width=200)
        narrow = self.render(width=60)
        self.assertNotIn("IN", narrow[0].split())
        self.assertTrue(any("lo" in line for line in wide))
        self.assertTrue(any("IN lo" in line for line in narrow))

    def test_a_dropped_wildcard_is_handed_back_as_nothing(self):
        # `*` says the rule does not narrow that field, and so does the absence
        # of the column.
        for line in self.render(width=60)[2:-2]:
            self.assertNotIn("IN *", line)
            self.assertNotIn("SOURCE *", line)

    def test_a_frame_given_a_height_stays_within_it(self):
        # Including heights with no room for a header and a footer, which are
        # not useful but must still be obeyed.
        for height in range(0, 45):
            self.assertLessEqual(len(self.render(height=height)), height,
                                 height)

    def test_what_did_not_fit_is_counted_in_the_footer(self):
        lines = self.render(height=12)
        # The body sits between the header rule and the blank line above the
        # footer; a row there is one that opens with a NUM.
        shown = sum(1 for row in lines[2:-2] if row[:3].strip().isdigit())
        found = re.search(r"\((\d+) below the screen\)", lines[-1])
        self.assertIsNotNone(found, lines[-1])
        self.assertEqual(shown + int(found.group(1)),
                         len(self.ruleset.rules))

    def test_what_did_not_fit_survives_a_narrow_footer(self):
        # The footer truncates from the right like any row, so the one part of
        # it that explains what is missing must not be the part that goes.
        self.assertIn("below the screen", self.render(width=40, height=12)[-1])

    def test_a_frame_that_fits_says_nothing_about_the_screen(self):
        self.assertNotIn("below the screen", self.render(height=200)[-1])
        self.assertNotIn("below the screen", self.render()[-1])

    def test_a_chain_heading_is_not_left_with_nothing_under_it(self):
        for height in range(4, 40):
            lines = self.render(height=height)
            self.assertFalse(lines[-3].startswith("Chain "), height)

    def test_a_line_is_a_row_with_no_embedded_newline(self):
        for line in self.render():
            self.assertNotIn("\n", line)

    def test_the_header_is_followed_by_a_rule(self):
        lines = self.render()
        self.assertTrue(lines[0].startswith("NUM"))
        self.assertEqual(set(lines[1]), {"-"})

    def test_grouping_puts_a_blank_line_before_each_chain_heading(self):
        lines = self.render()
        headings = [i for i, row in enumerate(lines)
                    if row.startswith("Chain ")]
        self.assertEqual(len(headings), 6)
        for i in headings:
            self.assertEqual(lines[i - 1], "")

    def test_a_chain_heading_carries_its_hook_and_policy(self):
        lines = self.render()
        self.assertIn("Chain input (inet filter, hook input, policy drop)",
                      lines)
        self.assertIn("Chain wan (inet filter)", lines)

    def test_flat_drops_the_headings_for_columns(self):
        lines = self.render(grouped=False)
        self.assertFalse(any(row.startswith("Chain ") for row in lines))
        self.assertTrue(lines[0].startswith("FAM"))

    def test_the_footer_counts_rules_and_counters(self):
        self.assertIn("16 rules, 14 with anonymous counters | interval 2s",
                      self.render()[-1])

    def test_the_footer_mentions_filtering_only_when_it_happened(self):
        self.assertIn("3 hidden by filters", self.render(hidden=3)[-1])
        self.assertNotIn("hidden", self.render(hidden=0)[-1])

    def test_the_footer_omits_the_interval_before_the_first_measurement(self):
        self.assertNotIn("interval", self.render(interval=None)[-1])

    def test_the_interval_prints_only_the_digits_it_was_given(self):
        self.assertIn("interval 2s", self.render(interval=2.0)[-1])
        self.assertIn("interval 0.25s", self.render(interval=0.25)[-1])

    def test_no_row_carries_trailing_padding(self):
        for line in self.render():
            self.assertEqual(line, line.rstrip(), repr(line))

    def test_color_does_not_change_the_column_grid(self):
        # Every width that drops a column, because dropping one is what hands
        # OPTIONS segments of its own to color: a grid that survives color at
        # one width can still lose a cell to it at another.
        for width in (140, 100, 60, 40):
            with self.subTest(width=width):
                plain = self.render(width=width, color=False)
                painted = [re.sub(r"\033\[[0-9;]*m", "", row)
                           for row in self.render(width=width, color=True)]
                self.assertEqual(plain, painted)

    def test_no_line_leaves_styling_open(self):
        # write_frame's erases run with whatever color is in effect, so a line
        # must not end mid-run. It need not end *at* the RESET: a row whose last
        # cell is unstyled trails plain text after one.
        for line in self.render(color=True):
            codes = re.findall(r"\033\[[0-9;]*m", line)
            if codes:
                self.assertEqual(codes[-1], nfrtop.RESET, repr(line))


# --------------------------------------------------------------------------
# golden frames


# The wide cases are wide enough that nothing is elided, so a diff shows a
# changed value rather than a changed ellipsis. The narrow ones are there for
# the shrinking itself.
#
# `sample` is the synthetic pair, packed with edge cases on purpose. `real` is a
# whole ruleset off a live box; it holds the parser to what an actual firewall
# produces rather than to what the fixture author thought to write down. Both
# were dumped from nftables 1.1.3 by the same `nft -j list ruleset` nfrtop
# calls. The real cases are wide and unelided because their job is to make every
# OPTIONS cell visible in a diff.
GOLDEN_CASES = {
    "grouped": dict(width=140, grouped=True, bits=False, color=False),
    "flat": dict(width=140, grouped=False, bits=False, color=False),
    "bits": dict(width=140, grouped=True, bits=True, color=False),
    "color": dict(width=140, grouped=True, bits=False, color=True),
    "medium": dict(width=100, grouped=True, bits=False, color=False),
    "narrow": dict(width=60, grouped=True, bits=False, color=False),
    # `color` is wide enough that no column is dropped, so the faint titles a
    # dropped column hands back to OPTIONS only appear on screen in this one.
    "color-narrow": dict(width=60, grouped=True, bits=False, color=True),
    "real-grouped": dict(width=200, grouped=True, bits=False, color=False,
                              sample="real"),
    "real-flat": dict(width=200, grouped=False, bits=False, color=False,
                           sample="real"),
}


def parse_fixture(sample):
    """Read a fixture the same way nfrtop reads a live ruleset."""
    return nfrtop.parse_ruleset(fixture(f"{sample}.json"))


def golden_frame(case):
    """Render a fixture pair exactly as a live second sample would be."""
    sample = case.get("sample", "sample")
    first = parse_fixture(sample)
    second = parse_fixture(f"{sample}-next")
    nfrtop.update_rates(second.rules, {r.key: r for r in first.rules}, INTERVAL)
    view = nfrtop.View(grouped=case["grouped"], bits=case["bits"],
                       color=case["color"])
    with terminal_width(case["width"]):
        lines = nfrtop.render_lines(second.rules, second.chains, view, INTERVAL)
    return "\n".join(lines) + "\n"


# Everything the parser fills in, minus the four that name the rule and so are
# already in its header line, and minus `text`, which is the parser's own
# working note rather than anything a reader sees. Rate is left out too: it
# belongs to update_rates, which the frames already cover.
PARSE_FIELDS = ("num", "order", "hook", "target", "proto", "iif", "oif",
                "saddr", "daddr", "options", "comment", "packets", "bytes")

# Golden name -> the fixture it dumps. The synthetic pair gets none: its edge
# cases are already pinned field by field by the unit tests above.
PARSE_DUMPS = {"real": "real"}


def parse_dump(name):
    """Every parsed field of every rule, verbatim.

    The frames above put their cells through the layout, which truncates a wide
    value to fit its column. That is right on screen and wrong for holding a
    parser to account: a value could lose its tail with the frame unchanged.
    There is no layout in here, so nothing hides.
    """
    parsed = parse_fixture(PARSE_DUMPS[name])
    lines = []
    for (family, table, chain), info in parsed.chains.items():
        lines.append(f"chain {family} {table} {chain} "
                     f"hook={info.hook!r} policy={info.policy!r}")
    for r in parsed.rules:
        lines.append("")
        lines.append(f"rule {r.family} {r.table} {r.chain} handle {r.handle}")
        for name in PARSE_FIELDS:
            lines.append(f"  {name} = {getattr(r, name)!r}")
    return "\n".join(lines) + "\n"


def escape(text):
    r"""Spell ESC as \e, so a golden file stays readable in a diff."""
    return text.replace("\033", r"\e")


def write_golden():
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for name, case in GOLDEN_CASES.items():
        path = GOLDEN / f"{name}.txt"
        path.write_text(escape(golden_frame(case)))
        print(f"wrote {path}")
    for name in PARSE_DUMPS:
        path = GOLDEN / f"{name}-parse.txt"
        path.write_text(parse_dump(name))
        print(f"wrote {path}")


class TestGoldenFrames(unittest.TestCase):
    """Whole frames for a fixed ruleset.

    These record current behavior rather than argue for it. Regenerate with
    `python3 test_nfrtop.py --update-golden` and read the diff: every line of it
    is a change someone will see on screen.
    """

    def check(self, name):
        expected = (GOLDEN / f"{name}.txt").read_text()
        self.assertEqual(escape(golden_frame(GOLDEN_CASES[name])), expected)

    def test_grouped(self):
        self.check("grouped")

    def test_flat(self):
        self.check("flat")

    def test_bits(self):
        self.check("bits")

    def test_color(self):
        self.check("color")

    def test_medium(self):
        self.check("medium")

    def test_narrow(self):
        self.check("narrow")

    def test_color_narrow(self):
        self.check("color-narrow")

    def test_real_grouped(self):
        self.check("real-grouped")

    def test_real_flat(self):
        self.check("real-flat")

    def check_parse(self, name):
        expected = (GOLDEN / f"{name}-parse.txt").read_text()
        self.assertEqual(parse_dump(name), expected)

    def test_real_parse(self):
        self.check_parse("real")

    def test_rates_reached_the_frame(self):
        frame = golden_frame(GOLDEN_CASES["grouped"])
        self.assertIn("100.0", frame)          # 200 packets over 2s
        self.assertIn("9.8KiB/s", frame)       # 20000 bytes over 2s

    def test_a_rule_without_a_counter_shows_dashes(self):
        for line in golden_frame(GOLDEN_CASES["grouped"]).splitlines():
            if "vmap" in line:
                self.assertIn("-", line)
                break
        else:
            self.fail("the vmap rule left the fixture")


class TestNextDeadline(unittest.TestCase):
    def test_an_on_time_cycle_advances_by_one_interval(self):
        now = time.monotonic()
        self.assertAlmostEqual(nfrtop.next_deadline(now, 2.0) - now, 2.0,
                               places=1)

    def test_a_deadline_left_behind_does_not_catch_up(self):
        # A 10s timeout on a 2s interval leaves five cycles owed. Paying them
        # back would start nft five times as fast as it can answer.
        now = time.monotonic()
        self.assertAlmostEqual(nfrtop.next_deadline(now - 10, 2.0) - now, 0.0,
                               places=1)


class TestNftFailures(unittest.TestCase):
    """What comes back when nft cannot be run, or will not answer."""

    def fails_with(self, exception):
        with mock.patch("subprocess.run", side_effect=exception):
            with self.assertRaises(RuntimeError) as caught:
                nfrtop.nft_rules()
        return str(caught.exception)

    def test_an_nft_that_never_answers_does_not_wait_for_ever(self):
        # Without a timeout a live session waits on it until it is killed,
        # showing neither a frame nor a warning while it does.
        message = self.fails_with(
            subprocess.TimeoutExpired(cmd="nft", timeout=nfrtop.NFT_TIMEOUT))
        self.assertIn("did not answer", message)

    def test_an_nft_that_will_not_start_says_why(self):
        self.assertIn("not found", self.fails_with(FileNotFoundError()))
        self.assertIn("could not run nft",
                      self.fails_with(PermissionError("Permission denied")))

    def test_how_nft_is_asked(self):
        # The exception tests above pass whether or not a timeout was ever
        # requested, so what was requested is checked here.
        done = subprocess.CompletedProcess([], 0, stdout='{"nftables": []}',
                                           stderr="")
        with mock.patch("subprocess.run", return_value=done) as run:
            nfrtop.nft_rules()
        args, kwargs = run.call_args
        self.assertEqual(args[0][1:], ["-j", "list", "ruleset"])
        self.assertEqual(kwargs["timeout"], nfrtop.NFT_TIMEOUT)
        # A ruleset may name a chain in bytes this cannot decode, and one of
        # them must not be the end of the session.
        self.assertEqual(kwargs["errors"], "replace")
        self.assertTrue(kwargs["text"])


class TestNftCommand(unittest.TestCase):
    """Which nft gets run, which is a question only root has a stake in."""

    def test_without_privileges_path_is_honored(self):
        # There is nothing to escalate to, and PATH is what lets an nft
        # installed somewhere unusual - or a stand-in - be run at all.
        with mock.patch("os.geteuid", return_value=1000):
            self.assertEqual(nfrtop.nft_command(), "nft")

    def test_as_root_a_system_location_comes_before_path(self):
        # Under sudo the PATH can still be the invoking user's, and a writable
        # directory on it would be a way to have something else run as root.
        found = os.path.join(nfrtop.NFT_DIRS[0], "nft")
        with mock.patch("os.geteuid", return_value=0), \
             mock.patch("os.path.isfile", lambda p: p == found), \
             mock.patch("os.access", lambda p, m: p == found):
            self.assertEqual(nfrtop.nft_command(), found)

    def test_as_root_with_nft_nowhere_expected_path_is_all_there_is(self):
        with mock.patch("os.geteuid", return_value=0), \
             mock.patch("os.path.isfile", lambda p: False):
            self.assertEqual(nfrtop.nft_command(), "nft")


class TestJsonWalker(unittest.TestCase):
    """The parts of the walk the real fixture has no example of."""

    def parse(self, *objects):
        return nfrtop.parse_ruleset(json.dumps({"nftables": [
            {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
            *objects,
        ]}))

    def rule(self, **fields):
        return {"rule": {"family": "inet", "table": "t", "chain": "c",
                         "handle": 1, **fields}}

    def test_an_empty_ruleset_is_not_an_error(self):
        parsed = self.parse()
        self.assertEqual(parsed.rules, [])
        self.assertEqual(parsed.chains, {})

    def test_a_rule_whose_statements_are_not_a_list_is_refused(self):
        # nft never sends this. A truncated pipe, or something else wearing
        # nft's name, might, and the difference should read as a message and
        # not as a traceback out of the middle of the render.
        with self.assertRaises(RuntimeError):
            self.parse(self.rule(expr=None))
        with self.assertRaises(RuntimeError):
            self.parse(self.rule(expr=7))

    def test_a_counter_that_is_not_a_count_is_refused(self):
        for value in ("lots", -1, True, 1.5, [1]):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    self.parse(self.rule(expr=[
                        {"counter": {"packets": value, "bytes": 1}}]))

    def test_a_counter_missing_a_side_is_no_counter_at_all(self):
        # nft always sends both, and half a counter cannot be subtracted from
        # half of another one, so it reads as a rule that does not count -
        # on both sides, and to --counted-only as well as to the columns.
        for half in ({"packets": 1}, {"bytes": 1}):
            with self.subTest(counter=half):
                rule = self.parse(self.rule(expr=[{"counter": half}])).rules[0]
                self.assertEqual((rule.packets, rule.bytes), (None, None))
                self.assertFalse(nfrtop.matches_filters(
                    rule, filter_args(counted_only=True)))

    def test_nesting_too_deep_to_walk_is_refused(self):
        # Spelled by hand: json.dumps cannot build this either, which is the
        # same limit parse_ruleset has to answer for rather than raise from.
        depth = 50000
        deep = ('{"nftables": [{"rule": {"expr": '
                + "[" * depth + '"x"' + "]" * depth + "}}]}")
        with self.assertRaises(RuntimeError):
            nfrtop.parse_ruleset(deep)

    def test_output_that_is_not_json_names_what_is_missing(self):
        # An nft built without libjansson prints the ruleset as text and exits
        # cleanly, so the only sign of trouble is what came back.
        with self.assertRaises(RuntimeError) as caught:
            nfrtop.parse_ruleset("table inet filter {\n}\n")
        self.assertIn("libjansson", str(caught.exception))

    def test_json_without_a_ruleset_in_it_says_so(self):
        with self.assertRaises(RuntimeError) as caught:
            nfrtop.parse_ruleset('{"metainfo": {}}')
        self.assertIn("libjansson", str(caught.exception))

    def test_a_rule_ahead_of_its_chain_still_gets_the_hook(self):
        # 0.9.6 lists a set between the chains and the rules, and nothing in the
        # schema promises this order at all, so the hook has to survive a rule
        # arriving first.
        rule = {"rule": {"family": "ip", "table": "t", "chain": "c",
                         "handle": 1, "expr": [{"accept": None}]}}
        chain = {"chain": {"family": "ip", "table": "t", "name": "c",
                           "handle": 1, "type": "filter", "hook": "input",
                           "prio": 0, "policy": "drop"}}
        self.assertEqual(self.parse(rule, chain).rules[0].hook, "input")

    def test_a_chain_without_a_hook_is_not_given_a_policy(self):
        chain = {"chain": {"family": "ip", "table": "t", "name": "c",
                           "handle": 1}}
        info = self.parse(chain).chains[("ip", "t", "c")]
        self.assertEqual((info.hook, info.policy), ("", ""))

    def test_a_base_chain_missing_its_policy_falls_back_to_accept(self):
        chain = {"chain": {"family": "ip", "table": "t", "name": "c",
                           "handle": 1, "hook": "input"}}
        self.assertEqual(self.parse(chain).chains[("ip", "t", "c")].policy,
                         "accept")

    def test_a_named_counter_object_is_not_a_rule(self):
        # The top level spells a named counter's definition and a rule that
        # bumps one with the same word. Only rules are rules.
        counter = {"counter": {"family": "ip", "table": "t", "name": "hits",
                               "handle": 1, "packets": 9, "bytes": 99}}
        self.assertEqual(self.parse(counter).rules, [])

    def test_a_kind_nobody_has_heard_of_is_skipped(self):
        self.assertEqual(self.parse({"gizmo": {"handle": 1}}).rules, [])

    def test_numbering_restarts_in_each_chain(self):
        def rule(chain, handle):
            return {"rule": {"family": "ip", "table": "t", "chain": chain,
                             "handle": handle, "expr": []}}

        parsed = self.parse(rule("a", 1), rule("a", 2), rule("b", 3))
        self.assertEqual([r.num for r in parsed.rules], [1, 2, 1])
        self.assertEqual([r.order for r in parsed.rules], [0, 1, 2])

    def test_a_stateless_counter_leaves_the_columns_empty(self):
        # nfrtop never passes -s, but null is what that flag produces and it
        # must not read as a counter of zero.
        rule = {"rule": {"family": "ip", "table": "t", "chain": "c",
                         "handle": 1, "expr": [{"counter": None}]}}
        parsed = self.parse(rule).rules[0]
        self.assertEqual((parsed.packets, parsed.bytes), (None, None))

    def test_the_body_ignores_the_counter_values(self):
        # Two samples of one unchanged rule must agree, or update_rates would
        # see a new rule every interval and never show a rate.
        def body(packets):
            return nfrtop.rule_body([
                {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                           "right": "lo"}},
                {"counter": {"packets": packets, "bytes": packets * 84}},
                {"accept": None},
            ])

        self.assertEqual(body(6), body(16))

    def test_the_body_still_notices_the_rule_itself_changing(self):
        counter = {"counter": {"packets": 0, "bytes": 0}}
        self.assertNotEqual(nfrtop.rule_body([counter, {"accept": None}]),
                            nfrtop.rule_body([counter, {"drop": None}]))

    def test_a_named_counter_is_part_of_what_the_rule_is(self):
        self.assertNotEqual(nfrtop.rule_body([{"counter": "hits"}]),
                            nfrtop.rule_body([{"counter": "misses"}]))


class TestJsonMatchers(unittest.TestCase):
    """Lifting matches into columns, past what the real fixture happens to hold."""

    def split(self, *statements):
        return nfrtop.split_rule(list(statements))

    def match(self, left, right, op="=="):
        return self.split({"match": {"op": op, "left": left, "right": right}})

    def meta(self, key, right, op="=="):
        return self.match({"meta": {"key": key}}, right, op)

    def payload(self, protocol, field, right, op="=="):
        return self.match({"payload": {"protocol": protocol, "field": field}},
                          right, op)

    # -- which side of the rule a match lands on --------------------------

    def test_every_spelling_of_an_interface_reaches_its_column(self):
        for key in ("iifname", "iif"):
            self.assertEqual(self.meta(key, "eth0")["iif"], "eth0", key)
        for key in ("oifname", "oif"):
            self.assertEqual(self.meta(key, "eth0")["oif"], "eth0", key)

    def test_the_protocol_can_be_matched_through_three_headers(self):
        self.assertEqual(self.meta("l4proto", "tcp")["proto"], "tcp")
        self.assertEqual(self.payload("ip", "protocol", "tcp")["proto"], "tcp")
        self.assertEqual(self.payload("ip6", "nexthdr", "tcp")["proto"], "tcp")

    def test_an_address_is_taken_from_any_network_header(self):
        for protocol in ("ip", "ip6", "inet", "ether"):
            self.assertEqual(self.payload(protocol, "saddr", "x")["saddr"], "x")
            self.assertEqual(self.payload(protocol, "daddr", "x")["daddr"], "x")

    def test_a_masked_match_stays_out_of_the_columns(self):
        # `meta mark & 0x03 == 0x01` wraps its left side in the operator, so
        # there is no plain field to name a column after.
        left = {"&": [{"meta": {"key": "mark"}}, "0x03"]}
        self.assertEqual(self.match(left, "0x01")["proto"], "")

    def test_a_raw_payload_match_stays_out_of_the_columns(self):
        left = {"payload": {"base": "th", "offset": 0, "len": 16}}
        self.assertEqual(self.match(left, 22)["proto"], "")

    def test_an_ordering_comparison_has_no_value_to_show(self):
        # There is no one address `ip saddr > 10.0.0.1` is about.
        self.assertEqual(self.payload("ip", "saddr", "10.0.0.1", ">")["saddr"],
                         "")

    def test_a_negated_match_carries_its_negation_into_the_column(self):
        self.assertEqual(self.meta("iifname", "lo", "!=")["iif"], "!=lo")

    def test_the_first_match_of_a_field_wins_the_column(self):
        fields = self.split(
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                       "right": "eth0"}},
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                       "right": "eth1"}},
        )
        self.assertEqual(fields["iif"], "eth0")

    # -- how a value is spelled -------------------------------------------

    def test_a_prefix_is_joined_back_into_slash_notation(self):
        right = {"prefix": {"addr": "10.0.0.0", "len": 8}}
        self.assertEqual(self.payload("ip", "saddr", right)["saddr"],
                         "10.0.0.0/8")

    def test_a_set_is_spelled_in_braces(self):
        right = {"set": ["10.0.0.1", "10.0.0.2"]}
        self.assertEqual(self.payload("ip", "saddr", right)["saddr"],
                         "{ 10.0.0.1, 10.0.0.2 }")

    def test_a_bare_list_is_a_set_too(self):
        # This is what `in` against several values looks like.
        right = ["10.0.0.1", "10.0.0.2"]
        self.assertEqual(self.payload("ip", "saddr", right, "in")["saddr"],
                         "{ 10.0.0.1, 10.0.0.2 }")

    def test_a_range_keeps_both_ends(self):
        right = {"range": ["10.0.0.1", "10.0.0.9"]}
        self.assertEqual(self.payload("ip", "saddr", right)["saddr"],
                         "10.0.0.1-10.0.0.9")

    def test_a_named_set_is_shown_by_its_name(self):
        self.assertEqual(self.payload("ip", "saddr", "@blocked")["saddr"],
                         "@blocked")

    def test_a_number_is_shown_as_written(self):
        self.assertEqual(self.meta("l4proto", "0x06")["proto"], "0x06")

    def test_a_protocol_number_is_named_where_it_can_be(self):
        self.assertEqual(self.meta("l4proto", 6)["proto"], "tcp")

    def test_an_unknown_protocol_number_stays_a_number(self):
        self.assertEqual(self.meta("l4proto", 253)["proto"], "253")

    def test_a_port_number_is_not_read_as_a_protocol(self):
        # proto_name() only ever sees the protocol column; 6 in a port is six.
        self.assertEqual(self.payload("tcp", "dport", 6)["proto"], "tcp")

    def test_a_map_lookup_is_left_for_options(self):
        right = {"map": {"key": {"meta": {"key": "mark"}}, "data": "@t"}}
        self.assertEqual(self.payload("ip", "saddr", right)["saddr"], "")

    def test_a_set_holding_a_concatenation_is_left_for_options(self):
        right = {"set": [{"concat": ["10.0.0.1", 80]}]}
        self.assertEqual(self.payload("ip", "saddr", right)["saddr"], "")

    # -- the protocol nft folded away --------------------------------------

    def test_a_transport_field_says_which_protocol_the_rule_is_about(self):
        for protocol in ("tcp", "udp", "sctp", "icmp", "icmpv6"):
            for field in ("dport", "sport", "flags", "type", "code"):
                fields = self.payload(protocol, field, 1)
                self.assertEqual(fields["proto"], protocol,
                                 f"{protocol} {field}")

    def test_a_concatenation_still_says_which_protocol(self):
        left = {"concat": [{"payload": {"protocol": "ip", "field": "saddr"}},
                           {"payload": {"protocol": "tcp", "field": "dport"}}]}
        self.assertEqual(self.match(left, {"set": []})["proto"], "tcp")

    def test_an_explicit_protocol_beats_the_hint(self):
        fields = self.split(
            {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}},
                       "right": "udplite"}},
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp",
                                            "field": "dport"}},
                       "right": 22}},
        )
        self.assertEqual(fields["proto"], "udplite")

    def test_a_network_header_is_not_a_protocol_hint(self):
        # `ip saddr` says nothing about what rides on top of ip.
        self.assertEqual(self.payload("ip", "saddr", "10.0.0.1")["proto"], "")


class TestJsonTargets(unittest.TestCase):
    """What a rule does with the packet, and the detail that goes beside it."""

    def split(self, statement):
        fields = nfrtop.split_rule([statement])
        return fields["target"], option_text(fields)

    # -- verdicts ----------------------------------------------------------

    def test_a_verdict_is_named_the_way_iptables_names_it(self):
        for key in ("accept", "drop", "return", "continue", "break"):
            self.assertEqual(self.split({key: None}), (key.upper(), ""), key)

    def test_a_jump_shows_the_chain_it_goes_to(self):
        self.assertEqual(self.split({"jump": {"target": "wan"}}), ("wan", ""))
        self.assertEqual(self.split({"goto": {"target": "wan"}}), ("wan", ""))

    def test_a_jump_to_nowhere_leaves_the_column_empty(self):
        # nft leaves this null when the rule names no chain.
        self.assertEqual(self.split({"jump": None}), ("", ""))

    def test_the_verdict_is_found_wherever_it_sits(self):
        fields = nfrtop.split_rule([
            {"counter": {"packets": 0, "bytes": 0}},
            {"accept": None},
        ])
        self.assertEqual(fields["target"], "ACCEPT")

    def test_a_rule_that_decides_nothing_has_no_target(self):
        fields = nfrtop.split_rule([{"log": {"prefix": "x"}}])
        self.assertEqual(fields["target"], "")

    # -- reject ------------------------------------------------------------

    def test_a_bare_reject_says_only_that_it_rejects(self):
        self.assertEqual(self.split({"reject": None}), ("REJECT", ""))

    def test_a_rejection_names_its_type_and_its_code(self):
        self.assertEqual(
            self.split({"reject": {"type": "icmpx",
                                   "expr": "admin-prohibited"}}),
            ("REJECT", "reject-with icmpx type admin-prohibited"))

    def test_a_tcp_reset_is_the_type_that_takes_no_code(self):
        self.assertEqual(self.split({"reject": {"type": "tcp reset"}}),
                         ("REJECT", "reject-with tcp reset"))

    def test_the_reason_for_a_rejection_is_one_of_nfts_words(self):
        # Nothing else can arrive here: a rejection can only name a reason nft
        # knows, so this needs no field to be asked about the way a match does.
        parts = nfrtop.reject_extra({"type": "icmp",
                                     "expr": "port-unreachable"})
        self.assertIn(("port-unreachable", nfrtop.SYMBOL), parts)
        # The family the reason is drawn from is not the reason.
        self.assertIn(("icmp", None), parts)

    # -- NAT ---------------------------------------------------------------

    def test_a_nat_shows_where_it_sends_the_packet(self):
        self.assertEqual(self.split({"snat": {"addr": "192.0.2.1"}}),
                         ("SNAT", "to:192.0.2.1"))

    def test_a_nat_with_a_port_shows_both(self):
        self.assertEqual(
            self.split({"dnat": {"addr": "10.0.0.5", "port": 8080}}),
            ("DNAT", "to:10.0.0.5:8080"))

    def test_a_redirect_names_a_bare_port(self):
        # No address, so no colon standing in for the one that is not there.
        self.assertEqual(self.split({"redirect": {"port": 8080}}),
                         ("REDIRECT", "to:8080"))

    def test_the_family_a_nat_names_is_kept(self):
        # nft names one only where the rule's family cannot settle it, which
        # is to say in an inet table, so this is not the FAM column repeated.
        self.assertEqual(
            self.split({"snat": {"family": "ip", "addr": "192.0.2.1"}}),
            ("SNAT", "ip to:192.0.2.1"))

    def test_a_nat_port_is_a_value_and_not_always_a_number(self):
        # A port range reaching str() would put a Python dict on the screen.
        self.assertEqual(
            self.split({"dnat": {"addr": "10.0.0.5",
                                 "port": {"range": [1000, 2000]}}}),
            ("DNAT", "to:10.0.0.5:1000-2000"))
        self.assertEqual(
            self.split({"redirect": {"port": {"range": [1000, 2000]}}}),
            ("REDIRECT", "to:1000-2000"))

    def test_a_nat_range_keeps_both_ends(self):
        addr = {"range": ["10.0.0.1", "10.0.0.9"]}
        self.assertEqual(self.split({"dnat": {"addr": addr}}),
                         ("DNAT", "to:10.0.0.1-10.0.0.9"))

    def test_a_masquerade_with_nothing_to_say_says_nothing(self):
        self.assertEqual(self.split({"masquerade": None}),
                         ("MASQUERADE", ""))

    # -- flags, however nft felt like writing them -------------------------

    def test_a_lone_flag_arrives_bare_rather_than_in_a_list(self):
        self.assertEqual(self.split({"masquerade": {"flags": "fully-random"}}),
                         ("MASQUERADE", "fully-random"))

    def test_several_flags_arrive_in_a_list(self):
        self.assertEqual(
            self.split({"masquerade": {"flags": ["random", "persistent"]}}),
            ("MASQUERADE", "random,persistent"))

    # -- queue -------------------------------------------------------------

    def test_a_queue_is_spelled_flags_then_destination(self):
        self.assertEqual(
            self.split({"queue": {"num": {"range": [0, 3]},
                                  "flags": "bypass"}}),
            ("QUEUE", "flags bypass to 0-3"))

    def test_a_queue_of_one_number_says_just_that(self):
        self.assertEqual(self.split({"queue": {"num": 3}}), ("QUEUE", "to 3"))

    def test_a_queue_with_no_tuning_is_still_a_queue(self):
        self.assertEqual(self.split({"queue": None}), ("QUEUE", ""))

    def test_a_queue_picked_per_packet_still_says_where(self):
        # `num` is not always a number: a numgen or a map picks one per packet,
        # and dropping it would leave the rule looking like it queued to 0.
        num = {"numgen": {"mode": "inc", "mod": 4}}
        self.assertEqual(self.split({"queue": {"num": num}}),
                         ("QUEUE", "to numgen mode inc mod 4"))

    # -- what is done to the packet along the way --------------------------

    def test_a_forward_is_a_target_because_it_ends_the_rule(self):
        # netdev ingress: the packet leaves by the named device and nothing
        # after this runs, which is what every other TARGET also means.
        self.assertEqual(self.split({"fwd": {"dev": "eth0"}}),
                         ("FWD", "dev eth0"))

    def test_a_tproxy_stands_in_the_column_when_nothing_else_does(self):
        self.assertEqual(
            self.split({"tproxy": {"addr": "127.0.0.1", "port": 50080}}),
            ("TPROXY", "to:127.0.0.1:50080"))

    def test_a_tproxy_names_the_family_where_nft_did(self):
        self.assertEqual(self.split({"tproxy": {"family": "ip",
                                                "port": 50080}}),
                         ("TPROXY", "ip to:50080"))

    def test_a_dup_says_both_where_and_out_of_what(self):
        self.assertEqual(
            self.split({"dup": {"addr": "10.0.0.1", "dev": "eth0"}}),
            ("DUP", "to:10.0.0.1 dev eth0"))

    def test_a_notrack_has_nothing_to_add_to_its_name(self):
        self.assertEqual(self.split({"notrack": None}), ("NOTRACK", ""))

    def test_the_verdict_still_wins_the_column(self):
        # `tproxy ... accept` is the usual way to write one, and the column is
        # for the verdict: saying TPROXY here would push `accept` into OPTIONS.
        fields = nfrtop.split_rule([
            {"tproxy": {"addr": "127.0.0.1", "port": 50080}},
            {"accept": None},
        ])
        self.assertEqual(fields["target"], "ACCEPT")
        self.assertEqual(option_text(fields),
                         "tproxy addr 127.0.0.1 port 50080")

    def test_a_verdict_before_the_action_wins_it_too(self):
        # The loop stops at the verdict, so the search for a fallback must not
        # have already settled on something it passed.
        fields = nfrtop.split_rule([{"notrack": None}, {"accept": None}])
        self.assertEqual(fields["target"], "ACCEPT")
        self.assertEqual(option_text(fields), "notrack")

    def test_the_first_action_is_the_one_the_column_falls_back_to(self):
        fields = nfrtop.split_rule([{"dup": {"addr": "10.0.0.1"}},
                                    {"notrack": None}])
        self.assertEqual(fields["target"], "DUP")
        # Nothing is dropped for having lost the column.
        self.assertIn("notrack", option_text(fields))


class TestJsonOptions(unittest.TestCase):
    """What is left of a rule once the columns have taken their share."""

    def options(self, *statements, comment=""):
        return option_text(nfrtop.split_rule(list(statements), comment))

    def split(self, *statements, comment=""):
        fields = nfrtop.split_rule(list(statements), comment)
        return option_text(fields), fields["comment"]

    def parts(self, *statements):
        return nfrtop.split_rule(list(statements))["option_parts"]

    # -- what does and does not survive into OPTIONS ------------------------

    def test_a_match_a_column_took_is_not_said_twice(self):
        self.assertEqual(self.options(
            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}},
                       "right": "lo"}}), "")

    def test_a_match_no_column_wanted_is_spelled_out(self):
        self.assertEqual(self.options(
            {"match": {"op": "==", "left": {"ct": {"key": "state"}},
                       "right": ["established", "related"]}}),
            "ct state { established, related }")

    def test_an_anonymous_counter_has_its_own_columns_already(self):
        self.assertEqual(self.options({"counter": {"packets": 1, "bytes": 2}}),
                         "")

    def test_a_second_anonymous_counter_is_spelled_out(self):
        # Only one of them can fill PKTS and BYTES. nftables evaluates left to
        # right, so the other counts something different, and dropping it
        # would take a number off the screen with nothing standing in for it.
        self.assertEqual(self.options(
            {"counter": {"packets": 1, "bytes": 2}},
            {"counter": {"packets": 77, "bytes": 7777}}),
            "counter packets 77 bytes 7777")

    def test_the_counter_that_fills_the_columns_is_the_first_one(self):
        expr = [{"counter": {"packets": 1, "bytes": 2}},
                {"counter": {"packets": 77, "bytes": 7777}}]
        self.assertEqual(nfrtop.rule_counter(expr), (1, 2))

    def test_a_named_counter_is_the_only_thing_the_rule_says_about_it(self):
        self.assertEqual(self.options({"counter": "hits"}),
                         'counter name "hits"')

    def test_the_verdict_detail_comes_after_the_statements(self):
        self.assertEqual(self.options(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "udp",
                                            "field": "dport"}},
                       "right": 53}},
            {"reject": {"type": "icmpx", "expr": "admin-prohibited"}}),
            "udp dport 53 reject-with icmpx type admin-prohibited")

    # The comment is an attribute of the rule, not a statement in it, so it is
    # kept out of OPTIONS and handed to the display separately: that is what
    # lets the display find it again to gray it out.
    def test_the_comment_is_not_part_of_the_options(self):
        self.assertEqual(self.split({"drop": None}, comment="blocklist"),
                         ("", "blocklist"))

    def test_a_comment_leaves_the_verdict_detail_alone(self):
        self.assertEqual(
            self.split({"masquerade": {"flags": "random"}}, comment="nat"),
            ("random", "nat"))

    # -- what the display draws each piece as --------------------------------

    def test_a_number_is_marked_where_nft_sent_a_number(self):
        self.assertIn(("22", nfrtop.NUMBER), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp",
                                            "field": "dport"}},
                       "right": 22}}))

    def test_a_quiet_word_is_marked_and_the_words_beside_it_are_not(self):
        parts = self.parts({"limit": {"rate": 10, "per": "second", "burst": 5}})
        self.assertIn(("rate", nfrtop.LABEL), parts)
        self.assertIn(("burst", None), parts)
        self.assertIn(("packets", None), parts)

    def test_a_field_name_is_quiet_only_where_the_list_says_so(self):
        self.assertIn(("type", nfrtop.LABEL), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "icmp",
                                            "field": "type"}},
                       "right": "echo-request"}}))
        self.assertIn(("dport", None), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "tcp",
                                            "field": "dport"}},
                       "right": 22}}))

    def test_a_statements_own_word_for_its_payload_is_quiet(self):
        # `value` is the mangle statement's word for the thing being written,
        # which is scaffolding around the value rather than the value; the
        # `key` beside it says what is being set and is the point of the rule.
        parts = self.parts({"mangle": {"key": {"meta": {"key": "mark"}},
                                       "value": 1}})
        self.assertIn(("value", nfrtop.LABEL), parts)
        self.assertIn(("mark", None), parts)
        self.assertIn(("1", nfrtop.NUMBER), parts)

    def test_the_name_of_a_named_counter_is_not_quiet(self):
        # `counter name "hits"` names the counter the rule is pointing at, so
        # it is as much what the rule says as the name itself is. The string
        # form is the named counter; the dict is the anonymous one, and that
        # gets lifted into PKTS and BYTES before it ever reaches OPTIONS.
        self.assertIn(("name", None), self.parts({"counter": "hits"}))

    def test_a_state_is_one_of_nfts_words_and_the_braces_around_it_are_not(self):
        parts = self.parts({"match": {"op": "==",
                                      "left": {"ct": {"key": "state"}},
                                      "right": ["established", "related"]}})
        self.assertIn(("established", nfrtop.SYMBOL), parts)
        self.assertIn(("related", nfrtop.SYMBOL), parts)
        # The set nft wrote around them is punctuation, not a state.
        self.assertIn(("{ ", None), parts)
        self.assertIn((", ", None), parts)

    def test_a_flag_is_one_of_nfts_words_through_an_operator(self):
        # `tcp flags syn|ack` is still that one field's value on both sides.
        parts = self.parts({"match": {"op": "==",
                                      "left": {"payload": {"protocol": "tcp",
                                                           "field": "flags"}},
                                      "right": {"|": ["syn", "ack"]}}})
        self.assertIn(("syn", nfrtop.SYMBOL), parts)
        self.assertIn(("ack", nfrtop.SYMBOL), parts)
        self.assertIn(("|", None), parts)

    def test_a_mask_does_not_hide_the_field_it_is_masking(self):
        # `tcp flags & (syn|rst) == syn` has three flag names in it: nft wraps
        # the field in an `&` to say which bits it is keeping, and the bits are
        # spelled in the same words the right side is.
        parts = self.parts(
            {"match": {"op": "==",
                       "left": {"&": [{"payload": {"protocol": "tcp",
                                                   "field": "flags"}},
                                      {"|": ["syn", "rst"]}]},
                       "right": "syn"}})
        self.assertEqual([(t, r) for t, r in parts if r == nfrtop.SYMBOL],
                         [("syn", nfrtop.SYMBOL), ("rst", nfrtop.SYMBOL),
                          ("syn", nfrtop.SYMBOL)])

    def test_an_operator_over_more_than_two_operands_is_still_an_operator(self):
        # nft sends `syn|rst|ack` as one `|` over three operands rather than as
        # nested pairs. A branch that insisted on two dropped the whole thing
        # through to the generic spelling, `| { syn, rst, ack }` - a set nft
        # never wrote, and one that took the flag names' role down with it.
        parts = self.parts(
            {"match": {"op": "==",
                       "left": {"&": [{"payload": {"protocol": "tcp",
                                                   "field": "flags"}},
                                      {"|": ["syn", "rst", "ack"]}]},
                       "right": "syn"}})
        self.assertEqual(plain(parts), "tcp flags & (syn | rst | ack) == syn")
        self.assertEqual([t for t, r in parts if r == nfrtop.SYMBOL],
                         ["syn", "rst", "ack", "syn"])

    def test_an_operator_on_the_right_gets_neither_parentheses_nor_equality(self):
        # Both are the masked case's, and this is not it: nothing here binds
        # against anything for a parenthesis to settle, and the field on the
        # left reads as it was typed.
        parts = self.parts({"match": {"op": "==",
                                      "left": {"payload": {"protocol": "tcp",
                                                           "field": "flags"}},
                                      "right": {"|": ["syn", "ack"]}}})
        self.assertEqual(plain(parts), "tcp flags syn | ack")

    def test_a_mask_over_an_ordinary_field_colors_nothing_extra(self):
        # The mask is looked through, not taken as a license to color: what is
        # behind this one is a mark, and a mark is this machine's own number.
        parts = self.parts({"match": {"op": "==",
                                      "left": {"&": [{"meta": {"key": "mark"}},
                                                     "0x03"]},
                                      "right": "0x01"}})
        self.assertEqual([p for p in parts if p[1] == nfrtop.SYMBOL], [])

    def test_what_a_value_is_matched_against_decides_it_rather_than_the_word(self):
        # The same string against a field that is not one of nft's vocabularies
        # is whatever this machine calls it, and nfrtop has nothing to add.
        self.assertIn(("established", None), self.parts(
            {"match": {"op": "==", "left": {"ct": {"key": "mark"}},
                       "right": "established"}}))

    def test_an_icmp_type_is_one_of_nfts_words(self):
        self.assertIn(("echo-request", nfrtop.SYMBOL), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "icmp",
                                            "field": "type"}},
                       "right": "echo-request"}}))

    def test_the_two_icmp_families_are_read_the_same_way(self):
        # An inet ruleset writes both, and a difference in color between them
        # would be read as a difference in the rules.
        self.assertIn(("nd-neighbor-solicit", nfrtop.SYMBOL), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "icmpv6",
                                            "field": "type"}},
                       "right": ["echo-request", "nd-neighbor-solicit"]}}))

    def test_a_numeric_icmp_code_is_a_number_rather_than_a_word(self):
        # Being a symbolic field does not make a number into a word: what nft
        # sent is what decides, and it sent this one as a quantity.
        self.assertIn(("3", nfrtop.NUMBER), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "icmp",
                                            "field": "code"}},
                       "right": 3}}))

    def test_a_value_matched_on_an_ordinary_field_is_left_alone(self):
        # `icmp type` is one of nft's vocabularies and `icmp id` is not, so the
        # same word is a word in one and a local number's name in the other.
        self.assertIn(("echo-request", None), self.parts(
            {"match": {"op": "==",
                       "left": {"payload": {"protocol": "icmp",
                                            "field": "id"}},
                       "right": "echo-request"}}))

    def test_a_concatenation_does_not_carry_one_fields_role_to_the_next(self):
        # `ct state . ip saddr` matches a pair; the address in it is an address
        # however the state beside it is read.
        parts = self.parts(
            {"match": {"op": "==",
                       "left": {"concat": [{"ct": {"key": "state"}},
                                           {"payload": {"protocol": "ip",
                                                        "field": "saddr"}}]},
                       "right": {"set": [{"concat": ["new", "10.0.0.1"]}]}}})
        self.assertIn(("new", None), parts)
        self.assertIn(("10.0.0.1", None), parts)

    def test_ruleset_text_reading_like_a_quiet_word_keeps_its_color(self):
        # QUIET_WORDS names words nfrtop writes. A set element that happens to
        # read `rate` came from the ruleset, never went through label(), and is
        # not nfrtop's to fade.
        parts = self.parts({"match": {"op": "==",
                                      "left": {"meta": {"key": "mark"}},
                                      "right": {"set": ["rate", "type"]}}})
        self.assertNotIn(("rate", nfrtop.LABEL), parts)
        self.assertNotIn(("type", nfrtop.LABEL), parts)

    # -- the words nft uses ------------------------------------------------

    def test_an_interface_needs_no_meta_keyword(self):
        # nft writes `iifname "eth0"`, not `meta iifname "eth0"`.
        self.assertEqual(self.options(
            {"match": {"op": "!=", "left": {"meta": {"key": "iiftype"}},
                       "right": "ether"}}), "meta iiftype != ether")
        self.assertEqual(plain(nfrtop.format_meta({"key": "iifname"})),
                         "iifname")

    def test_a_mark_keeps_the_meta_keyword(self):
        self.assertEqual(self.options(
            {"match": {"op": "==", "left": {"meta": {"key": "mark"}},
                       "right": 1}}), "meta mark 1")

    def test_a_masked_match_shows_its_mask(self):
        # nft writes `== 0x01` here and not elsewhere, and the left side says
        # which case this is: the `&` over the mark is a mask, where a plain
        # `meta mark 1` is a field and keeps its equality unwritten.
        left = {"&": [{"meta": {"key": "mark"}}, "0x03"]}
        self.assertEqual(self.options(
            {"match": {"op": "==", "left": left, "right": "0x01"}}),
            "meta mark & 0x03 == 0x01")

    def test_a_raw_payload_match_is_shown_the_way_nft_writes_one(self):
        left = {"payload": {"base": "th", "offset": 0, "len": 16}}
        self.assertEqual(self.options(
            {"match": {"op": "==", "left": left, "right": 22}}), "@th,0,16 22")

    def test_an_ordering_comparison_keeps_its_operator(self):
        self.assertEqual(self.options(
            {"match": {"op": ">",
                       "left": {"payload": {"protocol": "tcp",
                                            "field": "dport"}},
                       "right": 1024}}), "tcp dport > 1024")

    def test_a_concatenation_is_written_with_its_dots(self):
        left = {"concat": [{"payload": {"protocol": "ip", "field": "saddr"}},
                           {"payload": {"protocol": "tcp", "field": "dport"}}]}
        right = {"set": [{"concat": ["10.0.0.1", 80]}]}
        self.assertEqual(self.options({"match": {"op": "==", "left": left,
                                                 "right": right}}),
                         "ip saddr . tcp dport { 10.0.0.1 . 80 }")

    def test_a_direction_is_kept_where_a_ct_match_names_one(self):
        self.assertEqual(
            plain(nfrtop.format_ct({"key": "saddr", "dir": "original"})),
            "ct original saddr")

    def test_the_family_a_ct_match_names_is_kept(self):
        # In an inet table FAM says inet, and this says which of the two the
        # key is read as, so it is not the FAM column repeated.
        self.assertEqual(
            plain(nfrtop.format_ct({"key": "saddr", "dir": "original",
                                    "family": "ip6"})),
            "ct original ip6 saddr")

    def test_a_log_prefix_keeps_its_quotes(self):
        self.assertEqual(self.options({"log": {"prefix": "drop: "}}),
                         'log prefix "drop: "')

    def test_the_rest_of_a_log_follows_the_prefix(self):
        self.assertEqual(
            self.options({"log": {"prefix": "x", "level": "info"}}),
            'log prefix "x" level info')

    def test_a_rate_limit_is_written_as_a_rate(self):
        self.assertEqual(
            self.options({"limit": {"rate": 10, "burst": 5, "per": "second"}}),
            "limit rate 10/second burst 5 packets")

    def test_a_byte_limit_keeps_its_unit(self):
        self.assertEqual(
            self.options({"limit": {"rate": 1, "rate_unit": "mbytes",
                                    "per": "second"}}),
            "limit rate 1 mbytes/second")

    def test_an_inverted_limit_says_over(self):
        self.assertEqual(
            self.options({"limit": {"rate": 10, "per": "second",
                                    "inv": True}}),
            "limit over rate 10/second")

    def test_a_limit_key_nobody_knew_about_still_shows(self):
        self.assertEqual(
            self.options({"limit": {"rate": 10, "per": "second",
                                    "gizmo": 7}}),
            "limit rate 10/second gizmo 7")

    def test_a_vmap_shows_both_the_lookup_and_the_verdicts(self):
        vmap = {"vmap": {"key": {"meta": {"key": "iifname"}},
                         "data": {"set": [["eth0", {"jump": {"target": "wan"}}],
                                          ["eth1", {"drop": None}]]}}}
        self.assertEqual(self.options(vmap),
                         "iifname vmap { eth0 : jump wan, eth1 : drop }")

    def test_a_vmap_is_not_a_target(self):
        # The verdict is per lookup, so no one of them names the column.
        vmap = {"vmap": {"key": {"meta": {"key": "iifname"}},
                         "data": {"set": [["eth0", {"drop": None}]]}}}
        self.assertEqual(nfrtop.split_rule([vmap])["target"], "")

    # -- the statements nobody wrote a formatter for ------------------------

    def test_an_unknown_statement_is_laid_out_rather_than_dropped(self):
        self.assertEqual(self.options({"gizmo": {"a": 1, "b": "two"}}),
                         "gizmo a 1 b two")

    def test_an_unknown_statement_with_nothing_in_it_is_just_its_name(self):
        # nft sends a statement that takes no argument as a null, the way it
        # sends `notrack`; this one is not a statement nfrtop knows, so it is
        # the OPTIONS column that has to say it.
        self.assertEqual(self.options({"gizmo": None}), "gizmo")

    def test_an_unknown_statement_never_swallows_the_verdict(self):
        # This is the failure mode the rewrite is for: a statement nfrtop did
        # not recognize used to hide the verdict behind it.
        fields = nfrtop.split_rule([{"gizmo": {"a": 1}},
                                         {"accept": None}])
        self.assertEqual(fields["target"], "ACCEPT")
        self.assertEqual(option_text(fields), "gizmo a 1")

    def test_an_xt_statement_says_as_much_as_nft_gave_it(self):
        # nft says outright that it cannot translate these back into iptables
        # syntax, but the kind and the name are handed over and are worth more
        # than the bare word.
        self.assertEqual(self.options({"xt": {"type": "match",
                                              "name": "comment"}}),
                         "xt match comment")

    def test_an_xt_statement_with_nothing_to_go_on_still_names_itself(self):
        self.assertEqual(self.options({"xt": None}), "xt")

    def test_a_column_does_not_swallow_a_match_it_cannot_account_for(self):
        # A column takes a match over from OPTIONS, so a key it knows nothing
        # about would leave with it. Better an odd-looking OPTIONS than a rule
        # that quietly narrows more than the screen says.
        fields = nfrtop.split_rule([
            {"match": {"op": "==", "left": {"meta": {"key": "iifname",
                                                     "somethingnew": 1}},
                       "right": "lo"}}])
        self.assertEqual(fields["iif"], "")
        self.assertIn("somethingnew 1", option_text(fields))

    def test_a_key_no_formatter_knows_is_still_shown(self):
        for stmt, expected in (
            ({"reject": {"type": "icmpx", "somethingnew": 1}}, "somethingnew 1"),
            ({"queue": {"num": 3, "somethingnew": 1}}, "somethingnew 1"),
            ({"dnat": {"addr": "10.0.0.1", "somethingnew": 1}},
             "somethingnew 1"),
            ({"vmap": {"key": {"meta": {"key": "iifname"}}, "data": {"set": []},
                       "somethingnew": 1}}, "somethingnew 1"),
            ({"match": {"op": "==", "left": {"payload": {"protocol": "tcp",
                                                         "field": "dport"}},
                        "right": 22, "somethingnew": 1}}, "somethingnew 1"),
        ):
            with self.subTest(stmt=stmt):
                self.assertIn(expected, self.options(stmt))

    def test_a_value_of_no_known_shape_is_still_shown(self):
        self.assertEqual(self.options({"gizmo": {"a": {"x": 1, "y": 2}}}),
                         'gizmo a {"x": 1, "y": 2}')


# --------------------------------------------------------------------------
# the program as a whole


# The argv is logged and then checked, because "reads the ruleset and never
# writes it" is the whole promise of this program and a stand-in that prints
# the fixture whatever it is asked would not notice the day that stopped being
# true. `-s` would empty the counters; `flush ruleset` would empty the ruleset.
NFT_ARGV = "-j list ruleset"

FAKE_NFT = """#!/bin/sh
echo "$*" >> "$NFT_ARGV_LOG"
if [ "$*" != "%s" ]; then
    echo "nfrtop asked nft for: $*" >&2
    exit 99
fi
if [ -n "$NFT_FAIL" ]; then
    echo "$NFT_FAIL" >&2
    exit 1
fi
# An nft that answers the first time and not after: the log has one line per
# call, and this one has already added its own.
if [ -n "$NFT_FAIL_AFTER" ] \
   && [ "$(wc -l < "$NFT_ARGV_LOG")" -gt "$NFT_FAIL_AFTER" ]; then
    echo "transient failure" >&2
    exit 1
fi
if [ -n "$NFT_TEXT" ]; then
    cat %s
    exit 0
fi
if [ -n "$NFT_BIG" ]; then
    cat %s
    exit 0
fi
if [ -n "$NFT_NASTY" ]; then
    cat %s
    exit 0
fi
if [ -n "$NFT_WIDE" ]; then
    cat %s
    exit 0
fi
cat %s
"""


def wide_ruleset(path):
    """A ruleset whose comment is wider on screen than it is long."""
    path.write_text(json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
        {"chain": {"family": "inet", "table": "t", "name": "c", "handle": 1,
                   "type": "filter", "hook": "input", "prio": 0,
                   "policy": "accept"}},
        {"rule": {"family": "inet", "table": "t", "chain": "c", "handle": 1,
                  "expr": [{"counter": {"packets": 1, "bytes": 1}},
                           {"accept": None}],
                  "comment": "日本語のコメント" * 4}},
    ]}))


def nasty_ruleset(path):
    """A ruleset whose comment tries to talk to the terminal directly."""
    esc = chr(27)
    path.write_text(json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
        {"chain": {"family": "inet", "table": "t", "name": "c", "handle": 1,
                   "type": "filter", "hook": "input", "prio": 0,
                   "policy": "accept"}},
        {"rule": {"family": "inet", "table": "t", "chain": "c", "handle": 1,
                  "expr": [{"counter": {"packets": 1, "bytes": 1}},
                           {"accept": None}],
                  "comment": "pwn" + chr(10) + esc + "[2J" + esc + "]0;t"
                             + chr(7)}},
    ]}))

# Enough copies of the real ruleset that one frame cannot fit in a pipe buffer,
# which is the only condition under which a closed reader is met mid-write.
BIG_COPIES = 60


def big_ruleset(path):
    """Write a ruleset too large to be swallowed whole by a pipe."""
    top = json.loads((TESTS / "real.json").read_text())["nftables"]
    rules = [item for item in top if "rule" in item]
    grown = [item for item in top if "rule" not in item]
    handle = 10000
    for _ in range(BIG_COPIES):
        for item in rules:
            copy = json.loads(json.dumps(item))
            copy["rule"]["handle"] = handle
            handle += 1
            grown.append(copy)
    path.write_text(json.dumps({"nftables": grown}))


class FakeNft:
    """A stand-in for nft that prints the fixture.

    nft is Linux-only, so the fixture stands in for a ruleset here just as it
    does above. What it prints is the JSON dump, because that is what nfrtop
    now asks for, and the real one rather than the synthetic one, because
    driving the whole program is where a dump off a live box is worth most.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        bin_dir = Path(cls.tmp.name)
        big = bin_dir / "big.json"
        big_ruleset(big)
        nasty = bin_dir / "nasty.json"
        nasty_ruleset(nasty)
        wide = bin_dir / "wide.json"
        wide_ruleset(wide)
        fake = bin_dir / "nft"
        fake.write_text(FAKE_NFT % (NFT_ARGV, TESTS / "real.nft", big, nasty,
                                    wide, TESTS / "real.json"))
        fake.chmod(0o755)
        cls.argv_log = bin_dir / "argv.log"
        cls.env = dict(os.environ)
        cls.env["PATH"] = f"{bin_dir}:{cls.env['PATH']}"
        cls.env["COLUMNS"] = "100"
        cls.env["NFT_ARGV_LOG"] = str(cls.argv_log)

    def setUp(self):
        self.argv_log.write_text("")

    def nft_calls(self):
        """Every argv nfrtop handed to nft since this test started."""
        return self.argv_log.read_text().splitlines()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


# As root, nft_command() looks in the system locations before PATH, so the
# stand-in placed on PATH here would be bypassed and the tests would run
# against the real ruleset. Skipping says so; passing against the wrong nft
# would not. The root search itself is pinned by TestNftCommand.
NOT_ROOT = getattr(os, "geteuid", lambda: 1)() != 0


@unittest.skipUnless(hasattr(os, "fork"), "POSIX only")
@unittest.skipUnless(NOT_ROOT, "as root the fake nft on PATH is bypassed")
class TestProgram(FakeNft, unittest.TestCase):
    """Drive nfrtop.py as a process, with its output going to a pipe."""

    def run_nfrtop(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(NFRTOP), *args],
            capture_output=True, text=True, timeout=30,
            env={**self.env, **(env or {})},
        )

    def run_briefly(self, *args, seconds=0.8):
        """Start a live run, let it draw a few frames, then stop it."""
        proc = subprocess.Popen(
            [sys.executable, str(NFRTOP), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.env,
        )
        try:
            proc.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            pass
        proc.terminate()
        out, err = proc.communicate(timeout=10)
        return out, err

    def test_nft_is_only_ever_asked_to_list(self):
        # The read-only promise lives here. -s would empty the counters, and
        # anything that is not a list would be a change to the ruleset.
        done = self.run_nfrtop("--once", "--color", "never")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.nft_calls(), [NFT_ARGV])

    def test_one_frame_costs_one_call_to_nft(self):
        out, _ = self.run_briefly("-i", "0.2", "--color", "never")
        frames = out.count("NUM HNDL")
        self.assertGreaterEqual(frames, 2, "expected redraws")
        self.assertEqual(self.nft_calls(), [NFT_ARGV] * frames)

    def test_once_prints_a_snapshot_and_exits(self):
        done = self.run_nfrtop("--once", "--color", "never")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.startswith("NUM"))
        self.assertIn("25 rules, 23 with anonymous counters", done.stdout)

    def test_once_emits_no_escape_sequences(self):
        done = self.run_nfrtop("--once", "--color", "never")
        self.assertNotIn("\033", done.stdout)

    def test_a_redirected_live_run_stays_plain_text(self):
        # stdout is a pipe here, so the in-place redraw must not engage: its
        # erase sequences would end up as text in whatever is collecting this.
        out, _ = self.run_briefly("-i", "0.2", "--color", "never")
        self.assertNotIn("\033", out)
        self.assertGreaterEqual(out.count("NUM HNDL"), 2, "expected redraws")

    def test_missing_nft_is_reported(self):
        done = self.run_nfrtop("--once", env={"PATH": "/nonexistent"})
        self.assertEqual(done.returncode, 1)
        self.assertIn("'nft' command not found", done.stderr)

    def test_a_failing_nft_is_reported_with_its_own_message(self):
        done = self.run_nfrtop("--once", env={"NFT_FAIL": "boom"})
        self.assertEqual(done.returncode, 1)
        self.assertIn("nfrtop: boom", done.stderr)

    def test_a_comment_cannot_talk_to_the_terminal(self):
        # Whoever writes the ruleset is not always whoever reads it here, and
        # this is normally read as root. An ESC in a comment must arrive as
        # text, and a newline in one must not put a rule on two lines.
        done = self.run_nfrtop("--once", "--color", "never",
                               env={"NFT_NASTY": "1"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("\033", done.stdout)
        self.assertIn("\\x1b[2J", done.stdout)
        rows = [row for row in done.stdout.splitlines()
                if row[:3].strip() == "1"]
        self.assertEqual(len(rows), 1, done.stdout)

    def test_an_ascii_stdout_marks_what_it_cannot_carry(self):
        # A ruleset comment need not be ASCII and stdout need not be UTF-8:
        # `sudo LC_ALL=C nfrtop --once > out` is enough to meet both. The
        # escape must also be what the columns were sized for, so no row may
        # come out wider than the terminal because of it.
        done = self.run_nfrtop("--once", "--color", "never",
                               env={"PYTHONIOENCODING": "ascii",
                                    "NFT_WIDE": "1", "COLUMNS": "100"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("NUM", done.stdout)
        self.assertIn("\\u", done.stdout)
        for line in done.stdout.splitlines():
            self.assertLessEqual(len(line), 100, repr(line))

    def test_an_error_from_nft_cannot_talk_to_the_terminal_either(self):
        # nft's own stderr reaches the screen, and it is no more trusted than
        # the ruleset is.
        done = self.run_nfrtop("--once", env={"NFT_FAIL": "boom\033[2Jgone"})
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("\033", done.stderr)
        self.assertIn("\\x1b[2J", done.stderr)

    def test_a_permission_error_suggests_sudo(self):
        done = self.run_nfrtop(
            "--once", env={"NFT_FAIL": "Operation not permitted"})
        self.assertEqual(done.returncode, 1)
        self.assertIn("try running with sudo", done.stderr)

    def test_a_bad_interval_is_rejected(self):
        # nan fails every comparison, so `interval <= 0` lets it through and
        # time.sleep() is where it would have been caught, mid-session.
        # Spelled with '=' because -1 is the short form of --once, so `-i -1`
        # is argparse reading a flag where a value was meant to be.
        for bad in ("0", "-1", "nan", "inf"):
            with self.subTest(interval=bad):
                done = self.run_nfrtop("--once", f"--interval={bad}")
                self.assertEqual(done.returncode, 2)
                self.assertIn("--interval must be a finite number greater "
                              "than 0", done.stderr)

    def test_a_bad_min_rate_is_rejected(self):
        done = self.run_nfrtop("--min-rate", "fast")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--min-rate", done.stderr)

    def test_min_rate_is_refused_with_once(self):
        # One sample cannot yield a rate, so the threshold would have let every
        # counted rule through while looking as though it had filtered.
        done = self.run_nfrtop("--once", "--min-rate", "1M")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--min-rate needs two samples", done.stderr)

    def test_sorting_by_rate_is_refused_with_once(self):
        done = self.run_nfrtop("--once", "--sort", "rate")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--sort rate needs two samples", done.stderr)

    def test_an_ascii_stdout_survives_a_narrow_screen(self):
        # Truncation is what reaches for a character outside ASCII, so the
        # screen has to be narrow enough to force some.
        done = self.run_nfrtop("--once", "--color", "never",
                               env={"COLUMNS": "60", "PYTHONIOENCODING": "ascii"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("25 rules", done.stdout)
        self.assertNotIn("…", done.stdout)

    def test_a_closed_pipe_ends_the_run_quietly(self):
        # `nfrtop -1 | head`. A frame goes out in a single write, so a reader
        # that has stopped reading is met partway through it. Python's default
        # is to raise on that, and the run would end in a traceback rather than
        # in the silence the reader asked for, so SIGPIPE is left at SIG_DFL.
        proc = subprocess.Popen(
            [sys.executable, str(NFRTOP), "--once", "--color", "never"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**self.env, "NFT_BIG": "1"},
        )
        with proc.stdout as out:
            self.assertTrue(out.readline().startswith("NUM"))
        with proc.stderr as err:
            complaint = err.read()
        self.assertEqual(proc.wait(timeout=30), -signal.SIGPIPE)
        self.assertEqual(complaint, "")

    def test_the_version_is_printed_and_nft_is_never_run(self):
        # release.yml checks that __version__ matches the tag, so this is what
        # the released binary answers when asked which one it is. argparse
        # exits before the ruleset is read, and a --version that ran nft would
        # need a working one to answer at all.
        for flag in ("-V", "--version"):
            done = self.run_nfrtop(flag)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stdout.strip(),
                             f"nfrtop {nfrtop.__version__}", flag)
        self.assertEqual(self.nft_calls(), [])

    def test_an_nft_that_cannot_speak_json_is_reported(self):
        # -j is only compiled in against libjansson. Without it nft prints the
        # ruleset as text and exits 0, so nothing but the output gives it away.
        done = self.run_nfrtop("--once", env={"NFT_TEXT": "1"})
        self.assertEqual(done.returncode, 1)
        self.assertIn("libjansson", done.stderr)


@unittest.skipUnless(hasattr(os, "forkpty"), "needs a pty")
@unittest.skipUnless(NOT_ROOT, "as root the fake nft on PATH is bypassed")
class TestProgramOnATerminal(FakeNft, unittest.TestCase):
    """The same program, but talking to something that claims to be a screen."""

    def drive(self, args, seconds, sig=None, env=None):
        """Run nfrtop on a pty, stop it, and return everything it wrote."""
        import pty
        import time

        pid, fd = pty.fork()
        if pid == 0:                                     # pragma: no cover
            try:
                os.execvpe(sys.executable,
                           [sys.executable, str(NFRTOP), *args],
                           {**self.env, **(env or {})})
            finally:
                os._exit(127)

        def drain(until):
            chunk = b""
            while time.monotonic() < until:
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    time.sleep(0.02)
                    continue
                except OSError:          # the child closed the pty
                    break
                if not data:
                    break
                chunk += data
            return chunk

        os.set_blocking(fd, False)
        out = drain(time.monotonic() + seconds)
        if sig is not None:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass                     # it exited on its own, as --once does
            out += drain(time.monotonic() + 2.0)
        _, status = os.waitpid(pid, 0)
        os.close(fd)
        return out.decode("utf-8", "replace"), status

    def live(self, sig=signal.SIGINT):
        return self.drive(["-i", "0.2", "--color", "never"], 0.9, sig)

    def test_the_screen_is_never_blanked(self):
        out, _ = self.live()
        self.assertNotIn("\033[2J", out)

    def test_each_frame_homes_and_erases_behind_itself(self):
        out, _ = self.live()
        frames = out.count(nfrtop.SYNC_BEGIN)
        self.assertGreaterEqual(frames, 2, "expected repeated redraws")
        self.assertEqual(out.count(nfrtop.HOME), frames)
        self.assertEqual(out.count(nfrtop.CLEAR_EOS), frames)
        self.assertEqual(out.count(nfrtop.SYNC_END), frames)

    def test_the_cursor_is_hidden_once_and_restored_once(self):
        out, status = self.live()
        self.assertEqual(out.count(nfrtop.HIDE_CURSOR), 1)
        self.assertEqual(out.count(nfrtop.SHOW_CURSOR), 1)
        self.assertLess(out.index(nfrtop.HIDE_CURSOR),
                        out.index(nfrtop.SHOW_CURSOR))
        self.assertEqual(status, 0)

    def test_sigterm_gives_the_cursor_back(self):
        # The default disposition would skip the restore and leave the terminal
        # with no cursor at all.
        out, status = self.live(signal.SIGTERM)
        self.assertIn(nfrtop.SHOW_CURSOR, out)
        self.assertEqual(status, 0)

    def test_the_shell_gets_a_line_of_its_own_back(self):
        # A frame ends without a newline, so the cursor is left at the end of
        # the last row. Left there, the shell would start its prompt mid-line,
        # on top of the frame.
        out, status = self.live()
        self.assertTrue(out.replace("\r", "").endswith("\n" + nfrtop.SHOW_CURSOR),
                        "the last thing written should be a newline and the cursor")
        self.assertEqual(status, 0)

    def test_a_failure_after_the_first_sample_keeps_the_session_going(self):
        # The promise a live session is built on: a transient nft failure is a
        # complaint on stderr and a wait for the next deadline, not the end.
        # The frame already on screen is left standing rather than blanked.
        out, status = self.drive(["-i", "0.2", "--color", "never"], 0.9,
                                 signal.SIGINT, env={"NFT_FAIL_AFTER": "1"})
        self.assertEqual(status, 0)
        self.assertIn("nfrtop: transient failure", out)
        self.assertGreaterEqual(len(self.nft_calls()), 3,
                                "it gave up instead of trying the next one")
        self.assertEqual(out.count(nfrtop.SYNC_BEGIN), 1,
                         "only the one good sample should have drawn a frame")

    def test_a_session_that_drew_nothing_adds_no_blank_line(self):
        # Nothing was put on screen, so the cursor is still on the shell's own
        # line and the newline would only push the prompt down by one.
        out, status = self.drive(["-i", "0.2", "--color", "never"], 5.0,
                                 env={"NFT_FAIL": "Operation not permitted"})
        self.assertEqual(os.waitstatus_to_exitcode(status), 1)
        self.assertNotIn(nfrtop.SYNC_BEGIN, out)
        self.assertTrue(out.endswith(nfrtop.SHOW_CURSOR), repr(out[-40:]))

    def test_once_on_a_terminal_still_draws_no_screen_control(self):
        out, status = self.drive(["--once", "--color", "never"], 5.0)
        self.assertEqual(status, 0)
        self.assertIn("25 rules", out)
        for sequence in (nfrtop.HIDE_CURSOR, nfrtop.SYNC_BEGIN, nfrtop.HOME):
            self.assertNotIn(sequence, out)


if __name__ == "__main__":
    if "--update-golden" in sys.argv:
        sys.argv.remove("--update-golden")
        write_golden()
        sys.exit(0)
    unittest.main()
