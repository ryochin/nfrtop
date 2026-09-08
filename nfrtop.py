#!/usr/bin/env python3
"""
nfrtop.py - read-only live nftables rule/counter viewer.

Presents native nftables rules in an `iptables -L -n -v` style table: one rule
per line, with the common matchers (interfaces, addresses, protocol) lifted
into dedicated columns, plus cumulative counters and per-interval rates.

The name is netfilter-rule-top: unlike the connection-oriented tools in this
space, what is ranked here is the rules of the ruleset itself.

Requires: Python 3, and an `nft` that can emit JSON - that is, one built with
libjansson (nftables 0.9.0 or later). The ruleset is read through
`nft -j list ruleset`; there is no fallback to parsing the text output.

Run as a user allowed to read the nftables ruleset, typically:
    sudo python3 ./nfrtop.py
"""

__version__ = "0.1.0"

import argparse
import codecs
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Optional


# What the parser reads structure off. There is no grammar here and no regex:
# `nft -j` hands over the ruleset already taken apart, and these say which parts
# of it belong in which column.

# 'meta' keys that have a column of their own. nft spells an interface match
# four ways depending on whether it compares the name or the index.
META_COLUMNS = {
    "iifname": "iif",
    "iif": "iif",
    "oifname": "oif",
    "oif": "oif",
    "l4proto": "proto",
}
# Which network headers have addresses worth lifting into SOURCE and DEST.
ADDRESS_PROTOCOLS = frozenset(("ip", "ip6", "inet", "ether"))
# Where the network header names the protocol above it.
PROTOCOL_FIELDS = frozenset((("ip", "protocol"), ("ip6", "nexthdr")))
# Comparisons that yield a value to show. An ordering operator does not: there
# is nothing to put in a column for `tcp dport > 1024` but the rule itself.
VALUE_OPS = frozenset(("==", "!=", "in"))
# Operators that wrap the left of a match, as in `meta mark & 0x03 == 0x01`.
BINARY_OPS = frozenset(("&", "|", "^", "<<", ">>"))
# The meta keys nft writes without its own keyword in front. The real dump
# settles these four; anything else keeps the keyword, which is always valid
# nft even where nft itself would have left it off.
META_UNQUALIFIED = frozenset(("iif", "iifname", "oif", "oifname"))
# The parts of a rate limit that format_limit() spells out itself.
LIMIT_KEYS = frozenset(("inv", "rate", "rate_unit", "per", "burst",
                        "burst_unit"))

# A transport header whose fields only exist once the protocol is settled, so
# matching one of them says which protocol the rule is about.
TRANSPORT_PROTOCOLS = frozenset(("tcp", "udp", "udplite", "sctp", "dccp",
                                 "icmp", "icmpv6", "igmp"))
TRANSPORT_FIELDS = frozenset(("dport", "sport", "flags", "type", "code"))
# Statements that end a rule. A verdict is spelled the way iptables spells it,
# which is how the TARGET column has always read.
VERDICTS = frozenset(("accept", "drop", "return", "continue", "break"))
NAT_TARGETS = frozenset(("snat", "dnat", "masquerade", "redirect"))
TARGET_KEYS = (VERDICTS | NAT_TARGETS
               | frozenset(("jump", "goto", "reject", "queue", "fwd")))

# Statements that do something to the packet and let the rule carry on. The
# TARGET column falls back to these rather than being filled by them: `tproxy
# to :50080 accept` is a rule whose verdict is accept, and saying TPROXY there
# would push the verdict down into OPTIONS, which is the column's whole job.
# So they only stand where the rule reaches its end without a verdict - which
# is how `notrack` and `dup` are usually written.
PACKET_ACTIONS = frozenset(("tproxy", "dup", "notrack"))

# nft names a protocol where it can, so a number here is one it could not.
L4_PROTO_NAMES = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    33: "dccp",
    58: "icmpv6",
    132: "sctp",
    136: "udplite",
}

# nft can exit cleanly and still print something other than JSON, because -j is
# only compiled in when nftables was built against libjansson. Failing by hand
# beats failing as a stack trace over a half-read ruleset.
NOT_JSON = ("nft did not return JSON. 'nft -j' needs nftables 0.9 or newer, "
            "built with libjansson.")

ANY = "*"
OPTIONS_MIN_WIDTH = 16

RESET = "\033[0m"
FAINT = "\033[2m"       # de-emphasis; readable on both light and dark themes
GREEN = "\033[32m"      # traffic arriving; a packet let through
RED = "\033[31m"        # traffic leaving; a packet dropped on the floor
YELLOW = "\033[33m"     # transit and packet mangling; a named interface
MAGENTA = "\033[35m"    # a packet refused with an error back to the sender
CYAN = "\033[36m"       # an address or port rewritten
BLUE = "\033[34m"       # how to name a rule, as opposed to what it is doing
BOLD = "\033[1m"

# Screen control, as opposed to styling. A terminal that does not know the
# synchronized-update mode ignores the sequence, so it costs nothing to ask.
SYNC_BEGIN = "\033[?2026h"
SYNC_END = "\033[?2026l"
HOME = "\033[H"
CLEAR_EOL = "\033[K"    # from the cursor to the end of the line
CLEAR_EOS = "\033[J"    # from the cursor to the end of the screen
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

# Where a base chain sits decides which way its packets are going.
INBOUND_HOOKS = frozenset(("input", "ingress", "prerouting"))
OUTBOUND_HOOKS = frozenset(("output", "egress", "postrouting"))

# What a verdict does to the packet, rather than where the packet is headed.
# RETURN and CONTINUE decide nothing, so they stay as quiet as an empty cell.
TARGET_COLORS = {
    "ACCEPT": GREEN,
    "DROP": RED,
    "REJECT": MAGENTA,
    "SNAT": CYAN,
    "DNAT": CYAN,
    "MASQUERADE": CYAN,
    "REDIRECT": CYAN,
    # The decision is deferred to userspace rather than made here.
    "QUEUE": YELLOW,
    "RETURN": FAINT,
    "CONTINUE": FAINT,
}

# What a piece of OPTIONS is, as against what color it is drawn in: the parser
# says which pieces are numbers and which are the words holding them together,
# and the display alone decides what those are worth looking at.
#
# NUMBER is a value nft sent as a number, which is the only way to know one: a
# string of digits in a comment is not a number, and `22` is one whether it is
# read as a port or a mark. LABEL is a word a statement uses to introduce one of
# its own parts - the `rate` of `limit rate 10/second` - as against the name of
# the field itself, which is what the rule is actually about. SYMBOL is a value
# out of nft's own vocabulary, as against one out of this machine's.
NUMBER = "number"
LABEL = "label"
SYMBOL = "symbol"
OPTION_COLORS = {NUMBER: GREEN, LABEL: FAINT, SYMBOL: CYAN}

# The fields whose values are words nft defines rather than names this machine
# happens to use: `established` and `syn` mean the same thing on every host,
# where `eth0` and `10.0.0.1` are local facts nfrtop has nothing to add to.
#
# Which side of a match a string sits on is the only thing that can say this.
# `established` is a bare string in the JSON, indistinguishable from a set name
# or anything else the ruleset spells the same way, so the field it is being
# compared against is what settles it - and a word list would have colored the
# `established` in a comment along with it.
#
# Keyed by (what nft called the left side, what it called the field): a
# statement kind for `ct`, a protocol for the rest. No protocol is named `ct`,
# so the two namespaces share this set without colliding.
#
# Both ICMP families are here because they are the same rule written twice: an
# inet ruleset says `icmp type echo-request` and `icmpv6 type echo-request`
# side by side, and coloring one of them would look like a distinction being
# drawn. `code` keeps `type` company for the same reason - `admin-prohibited`
# is one of nft's words whichever of the two it is given to. A numeric code
# arrives as a number and is a NUMBER, which is decided before this is asked.
SYMBOLIC_FIELDS = frozenset((
    ("ct", "state"),
    ("tcp", "flags"),
    ("icmp", "type"), ("icmp", "code"),
    ("icmpv6", "type"), ("icmpv6", "code"),
))

# Which of the words nfrtop writes are worth dimming, named one by one rather
# than by rule. Being scaffolding is not on its own a reason to fade: `burst`
# and `packets` are read as often as the numbers beside them, and a unit that
# has gone quiet is a number that no longer says what it counts. The list is
# short and explicit so that changing one's mind about a word is changing this
# line, and a word can only reach it by having been written here - a set
# element or a comment that happens to read `rate` is ruleset text and keeps
# its own color.
QUIET_WORDS = frozenset(("prefix", "level", "value", "type", "rate", "over"))
RATE_RE = re.compile(r'^(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?(?:ps|/s)?$', re.I)


@dataclass
class Rule:
    family: str
    table: str
    chain: str
    handle: int
    packets: Optional[int]
    bytes: Optional[int]
    text: str
    order: int
    # 1-based position within the chain, like iptables --line-numbers. The
    # handle is nft's stable identity and is what `nft delete rule` takes.
    num: int = 0
    # The hook of the enclosing base chain, empty for a user-defined chain.
    # Denormalized from ChainInfo so a rule alone is enough to color a row.
    hook: str = ""
    target: str = ""
    proto: str = ""
    iif: str = ""
    oif: str = ""
    saddr: str = ""
    daddr: str = ""
    # OPTIONS as (text, role) pairs rather than one string: the roles are what
    # the display colors by, and a role cannot be recovered from finished
    # text. `options` below is the plain reading of these.
    option_parts: list = field(default_factory=list)
    # The rule's own comment, kept out of OPTIONS so that the display can tell
    # it apart without having to find it again in a finished string.
    comment: str = ""
    pps: Optional[float] = None
    bps: Optional[float] = None
    # Whether this rule has passed anything since nfrtop started. Sticky, and
    # carried forward from sample to sample, so a rule that has fallen quiet
    # stays distinguishable from one that has never matched at all.
    was_active: bool = False

    @property
    def options(self):
        """What OPTIONS says, with the roles the display draws it by left out."""
        return "".join(text for text, _ in self.option_parts)

    @property
    def key(self):
        # The handle alone would not do: nft hands the same handle out again
        # after a ruleset reload, and subtracting one rule's counters from an
        # unrelated rule's would invent a rate. The body settles it, and it is
        # already free of the volatile counter values.
        return (self.family, self.table, self.chain, self.handle, self.text)

    @property
    def chain_key(self):
        return (self.family, self.table, self.chain)


@dataclass
class ChainInfo:
    hook: str = ""
    policy: str = ""


@dataclass
class Ruleset:
    rules: list = field(default_factory=list)
    chains: dict = field(default_factory=dict)


@dataclass
class View:
    """How to draw the table, as opposed to what to draw."""
    grouped: bool = True
    bits: bool = False
    color: bool = False


# Where a system that keeps nft where it belongs keeps it.
NFT_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin",
            "/usr/local/bin")

# Long enough that no `nft list ruleset` on a real box comes near it, short
# enough that an nft which has stopped answering does not take the display
# down with it: without this, a live session waits for it for ever.
NFT_TIMEOUT = 10.0


def nft_command():
    """The nft to run: a system location as root, and PATH otherwise.

    This program is normally run under sudo, and under sudo the PATH can still
    be the invoking user's - `sudo -E`, an env_keep, a secure_path someone
    relaxed - so a writable directory early on it would be a way to have
    something other than nft run as root. Looking where nft belongs first costs
    nothing on a system where it is there, which is every system where it is
    installed at all.

    Without privileges there is nothing to escalate to, so PATH is honored as
    it always was; that is also what makes a stand-in nft testable.
    """
    if os.geteuid() != 0:
        return "nft"
    for directory in NFT_DIRS:
        path = os.path.join(directory, "nft")
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # Not where it belongs, so no better answer than the one PATH gives.
    return "nft"


def nft_rules():
    """Read the ruleset as JSON, which is the only form nft calls an interface.

    -a is not asked for: the JSON always carries handles. -n is not asked for
    either, so nft names what it can and the screen says `tcp flags syn` rather
    than `tcp flags 0x2`. -s must never be asked for: it empties the counters,
    which are the point of this program.
    """
    try:
        p = subprocess.run(
            [nft_command(), "-j", "list", "ruleset"],
            text=True,
            # nft names chains and interfaces in whatever the ruleset used, and
            # a byte that is not valid here must not be the end of the session.
            errors="replace",
            # Both streams: stdout carries the ruleset, and stderr carries the
            # only account of why there is none.
            capture_output=True,
            timeout=NFT_TIMEOUT,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("'nft' command not found")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nft did not answer within {NFT_TIMEOUT:g}s")
    except OSError as e:
        raise RuntimeError(f"could not run nft: {e}")

    if p.returncode != 0:
        msg = p.stderr.strip() or f"nft exited with status {p.returncode}"
        raise RuntimeError(msg)

    return parse_ruleset(p.stdout)


def counter_index(expr):
    """Where in a rule the counter that fills PKTS and BYTES sits, or None.

    'counter' arrives in three shapes: a dict for the anonymous counter that
    carries the values, a string when the rule only bumps a named counter
    somewhere else, and null under --stateless. Only the dict has anything to
    put in a column, so the other two read as no counter at all.

    A rule may carry more than one anonymous counter, and each counts what
    reached its own position. The first fills the columns; the rest are spelled
    out in OPTIONS, where their position is visible, rather than dropped.
    """
    for i, stmt in enumerate(expr):
        if isinstance(stmt, dict) and isinstance(stmt.get("counter"), dict):
            return i
    return None


def rule_counter(expr):
    """The packets and bytes of a rule's anonymous counter, or a pair of Nones.

    What this counts is whatever reached the counter's place in the rule, not
    whatever the rule as a whole matched: nftables evaluates left to right, so
    a counter written before a match counts more than the match admits.
    """
    i = counter_index(expr)
    if i is None:
        return None, None
    counter = expr[i]["counter"]
    packets, nbytes = counter.get("packets"), counter.get("bytes")
    # Half a counter cannot be subtracted from half of another one, and a rule
    # showing a packet count beside an empty BYTES would look like a rule that
    # had moved no bytes. Either both sides are there or there is no counter.
    if packets is None or nbytes is None:
        return None, None
    return packets, nbytes


def rule_body(expr):
    """A stable string for the rule, free of the counter values that move.

    This is what tells two rules apart when nft has handed the same handle out
    twice; see Rule.key. The values are dropped rather than the counter itself,
    so a rule that gained one still reads as a different rule.
    """
    stable = []
    for stmt in expr:
        if isinstance(stmt, dict) and isinstance(stmt.get("counter"), dict):
            stmt = dict(stmt, counter=None)
        stable.append(stmt)
    return json.dumps(stable, sort_keys=True)


def match_column(left):
    """Which column a match belongs in, or None to leave it in OPTIONS.

    Anything that is not a plain header field lands here too and is turned
    down: a masked match wraps its left side in an operator, `{"&": [...]}`, and
    a raw payload match gives an offset and a length instead of a field name.
    Neither has a value a column could show.
    """
    if not isinstance(left, dict) or len(left) != 1:
        return None
    kind, spec = next(iter(left.items()))
    if not isinstance(spec, dict):
        return None
    # A column takes over a match and stops OPTIONS from repeating it, so it
    # may only take one it accounts for completely. A key nobody here knows
    # about would otherwise leave with the column that swallowed it.
    if kind == "meta":
        if set(spec) - {"key"}:
            return None
        return META_COLUMNS.get(spec.get("key"))
    if kind == "payload":
        if set(spec) - {"protocol", "field"}:
            return None
        protocol, field = spec.get("protocol"), spec.get("field")
        if field in ("saddr", "daddr") and protocol in ADDRESS_PROTOCOLS:
            return field
        if (protocol, field) in PROTOCOL_FIELDS:
            return "proto"
    return None


def is_column_value(right):
    """Whether a matched value is one value, and so fit to sit in a column.

    A concatenation or a map lookup puts syntax where the value would be, and a
    column showing `.` teaches nobody anything. Those are left to OPTIONS,
    where there is room to spell them out in full.
    """
    if isinstance(right, (bool, str, int, float)):
        return True
    if isinstance(right, list):
        # An inline list is what an `in` against several values looks like.
        return all(is_column_value(v) for v in right)
    if isinstance(right, dict) and len(right) == 1:
        kind, spec = next(iter(right.items()))
        if kind == "prefix":
            return isinstance(spec, dict)
        if kind == "set":
            return isinstance(spec, list) and all(map(is_column_value, spec))
        if kind == "range":
            return (isinstance(spec, list) and len(spec) == 2
                    and all(map(is_column_value, spec)))
    return False


def match_value(right):
    """Spell a matched value for a column, or None if it does not belong in one."""
    return format_value(right) if is_column_value(right) else None


def label(text):
    """A word nfrtop wrote to introduce a part of a statement.

    Whether it is drawn faint is QUIET_WORDS' to say. Going through here is
    what makes that a decision about nfrtop's own words: the same text arriving
    from the ruleset never passes this way and so is never dimmed.
    """
    text = str(text)
    return [(text, LABEL if text in QUIET_WORDS else None)]


def punctuated(groups, sep):
    """Join groups of segments with punctuation belonging to neither side.

    Unlike joined(), an empty group still takes its separator: `{ 22, , 80 }`
    is what a set with an unspellable member looks like, and losing the gap
    would say the set had two members rather than three.
    """
    out = []
    for i, group in enumerate(groups):
        if i:
            out.append((sep, None))
        out.extend(group)
    return out


def joined(groups, sep=" "):
    """Join the groups of segments that have anything in them.

    This is `sep.join(part for part in parts if part)` over segments: a part
    that came out empty takes no separator with it, so nothing is spaced out
    around a word that was never there.
    """
    out = []
    for group in groups:
        group = [(text, role) for text, role in group if text]
        if not group:
            continue
        if out:
            out.append((sep, None))
        out.extend(group)
    return out


def is_binop(value):
    """Whether nft sent this value as an operator over operands.

    The one shape two callers both need to recognize: value_segments(), to know
    that an operand needs the parentheses that say how it binds, and
    format_match(), to know that its left side is a masked field and so is the
    case nft writes the `==` out for.
    """
    return (isinstance(value, dict) and len(value) == 1
            and next(iter(value)) in BINARY_OPS)


def set_segments(items, plain=None):
    """A set the way nft writes one."""
    if not items:
        return [("{ }", None)]
    return [("{ ", None),
            *punctuated([value_segments(i, plain) for i in items], ", "),
            (" }", None)]


def value_segments(value, plain=None):
    """Spell any value at all, however deeply nft nested it, in pieces.

    This one never gives up. Whether a value is fit for a column is a separate
    question, asked by is_column_value(); here the only job is to say what is
    there, because a value that cannot be spelled is a value that disappears.

    A number is picked out here because here is the only place that can: nft
    sent it as a number, and once it is text a port is indistinguishable from
    any other run of digits the ruleset happened to contain.

    `plain` is the role a bare string takes. It is None nearly everywhere - a
    string in a rule is a name out of this machine's world, and nothing about
    the string itself says otherwise - and is set by a caller that has read
    enough of the surrounding structure to know better, as format_match() has
    when the field being matched is one of SYMBOLIC_FIELDS. It follows the
    value down through sets, ranges and operators, which are all still the one
    field's value, and stops at a concatenation, which is several fields'.
    """
    if value is None:
        return []
    if isinstance(value, bool):
        # Ahead of the number case: in Python a bool is one, and 'True' is not
        # how nft spells anything. Nor is it a quantity, so it is not a NUMBER.
        return [("true" if value else "false", None)]
    if isinstance(value, (int, float)):
        return [(str(value), NUMBER)]
    if isinstance(value, str):
        return [(value, plain)]
    if isinstance(value, list):
        return set_segments(value, plain)
    if isinstance(value, dict) and len(value) == 1:
        kind, spec = next(iter(value.items()))
        if kind == "prefix" and isinstance(spec, dict):
            # nft has already normalized the address, so this is a join. The
            # length is part of the address rather than a quantity of its own.
            return [(f"{spec.get('addr')}/{spec.get('len')}", None)]
        if kind == "set" and isinstance(spec, list):
            return set_segments(spec, plain)
        if kind == "range" and isinstance(spec, list):
            return punctuated([value_segments(v, plain) for v in spec], "-")
        if kind == "concat" and isinstance(spec, list):
            # Each member is a different field, so what the caller knew about
            # the first of them says nothing about the rest.
            return punctuated([value_segments(v) for v in spec], " . ")
        if kind == "payload" and isinstance(spec, dict):
            return format_payload(spec)
        if kind == "meta" and isinstance(spec, dict):
            return format_meta(spec)
        if kind == "ct" and isinstance(spec, dict):
            return format_ct(spec)
        if kind == "map" and isinstance(spec, dict):
            return joined([value_segments(spec.get("key")), [("map", None)],
                           format_map_data(spec.get("data"))])
        if kind in BINARY_OPS and isinstance(spec, list) and len(spec) >= 2:
            # An operand count rather than a pair: nft sends `syn|rst|ack` as
            # one operator over three operands, not as nested pairs, and a
            # branch that insisted on two dropped it through to the generic
            # spelling - `| { syn, rst, ack }`, which is a set nft never wrote.
            #
            # Every operand is the same field's value, so `plain` reaches all
            # of them: `tcp flags & (syn | rst | ack)` is three flag names.
            groups = []
            for i, operand in enumerate(spec):
                if i:
                    groups.append([(kind, None)])
                inner = value_segments(operand, plain)
                # An operand that is itself an operator gets the parentheses
                # nft writes around it. A mask is the case that matters: with
                # the flags run together as `tcp flags & syn | rst | ack`, the
                # reader is left to guess which of the two binds first, and a
                # viewer of a firewall must not leave that to be guessed.
                if is_binop(operand):
                    inner = [("(", None), *inner, (")", None)]
                groups.append(inner)
            return joined(groups)
        # Whatever is left is shaped like a statement, and a verdict inside a
        # map is exactly that.
        return statement_segments(value)
    return [(json.dumps(value, sort_keys=True), None)]


def format_value(value):
    """What value_segments() says, with the roles left out."""
    return "".join(text for text, _ in value_segments(value))


def format_payload(spec):
    """`tcp dport`, or nft's own `@th,0,16` where the match is on raw bytes.

    The field goes through label() so that QUIET_WORDS gets a say in it: the
    `type` of `icmp type echo-request` is nft's word for where to look rather
    than anything about this rule, where the `dport` of `tcp dport 22` is the
    whole point of the match. Which is which is that list's to decide.
    """
    protocol, field = spec.get("protocol"), spec.get("field")
    if protocol and field:
        return with_rest(joined([[(str(protocol), None)], label(field)]),
                         spec, "protocol", "field")
    raw = "@{},{},{}".format(spec.get("base"), spec.get("offset"),
                             spec.get("len"))
    return with_rest([(raw, None)], spec, "base", "offset", "len")


def format_meta(spec):
    """`iifname`, or `meta mark` where nft needs its keyword to disambiguate."""
    key = spec.get("key")
    text = label(key) if key in META_UNQUALIFIED \
        else joined([[("meta", None)], label(key)])
    return with_rest(text, spec, "key")


def format_ct(spec):
    """`ct state`, or `ct original ip saddr` where a direction and family are.

    The family is not the FAM column repeated: in an inet table FAM says inet
    and this says which of the two address families the key is read as, so
    dropping it would drop the only place that is written down.
    """
    parts = [[("ct", None)]]
    for part in (spec.get("dir"), spec.get("family")):
        if part:
            parts.append([(str(part), None)])
    if spec.get("key"):
        parts.append(label(spec["key"]))
    return with_rest(joined(parts), spec, "dir", "family", "key")


def format_map_data(data):
    """The body of a map, whose members are pairs rather than plain values."""
    elements = data.get("set") if isinstance(data, dict) else None
    if not isinstance(elements, list):
        return value_segments(data)
    shown = []
    for elem in elements:
        if isinstance(elem, list) and len(elem) == 2:
            shown.append(punctuated([value_segments(elem[0]),
                                     value_segments(elem[1])], " : "))
        else:
            shown.append(value_segments(elem))
    if not shown:
        return [("{ }", None)]
    return [("{ ", None), *punctuated(shown, ", "), (" }", None)]


def proto_name(value):
    """Name an L4 protocol given as a number, or hand back what came in."""
    try:
        return L4_PROTO_NAMES.get(int(value), value)
    except ValueError:
        return value


def proto_hint(node):
    """The transport protocol implied by matching one of its own fields.

    This is not a nicety. nft folds a redundant match away, so a rule written
    `meta l4proto icmp icmp type echo-request` comes back with the l4proto
    match gone and this is the only thing left that says icmp. The search is
    recursive because a concatenation buries the header a level down:
    `ip saddr . tcp dport` says tcp just as plainly as `tcp dport` does.
    """
    if isinstance(node, dict):
        payload = node.get("payload")
        if isinstance(payload, dict):
            protocol = payload.get("protocol")
            if (protocol in TRANSPORT_PROTOCOLS
                    and payload.get("field") in TRANSPORT_FIELDS):
                return protocol
        children = node.values()
    elif isinstance(node, list):
        children = node
    else:
        return None

    for child in children:
        found = proto_hint(child)
        if found:
            return found
    return None


def target_flags(spec):
    """The flags of a NAT or queue statement, however many there are.

    nft writes a lone flag bare and several in a list. The source reads as
    though it were always a list; the dump off the real box says otherwise, so
    take both.
    """
    flags = spec.get("flags")
    if isinstance(flags, str):
        return [flags]
    if isinstance(flags, list):
        return [str(f) for f in flags]
    return []


def reject_extra(spec):
    """How a rejection is spelled, in the words nft uses for it.

    'tcp reset' is the one type with no code to name after it, and so also the
    one that does not take the word 'type'.

    The code is one of nft's own words - `port-unreachable` reads the same on
    every host - so it is a SYMBOL without having to be asked about. Nothing
    else can arrive here: unlike a match, whose right side is whatever the
    ruleset chose, a rejection can only name a reason nft knows. The type
    beside it is the family the reason is drawn from rather than the reason,
    and is left in the default color as `icmp` is in `icmp type echo-request`.
    """
    if not isinstance(spec, dict):
        return []
    kind, code = spec.get("type"), spec.get("expr")
    if kind and code is not None:
        parts = [[("reject-with", None)], [(str(kind), None)],
                 label("type"), value_segments(code, SYMBOL)]
    elif kind:
        parts = [[("reject-with", None)], [(str(kind), None)]]
    elif code is not None:
        parts = [[("reject-with", None)], value_segments(code, SYMBOL)]
    else:
        parts = []
    return with_rest(joined(parts), spec, "type", "expr")


def nat_extra(spec):
    """Where a NAT statement sends the packet, and how it chooses.

    nft names a family here only where the rule's own family cannot settle it,
    which is to say in an inet table, where FAM says inet and this says which
    of the two the address is. It is not the FAM column repeated, so it stays.

    A redirect names a bare port, and 'to::8080' would be a colon too many.
    Neither the address nor the port is required to be a literal: either can be
    a range, a map or a numgen, so both go through format_value().
    """
    if not isinstance(spec, dict):
        return []
    addr, port = spec.get("addr"), spec.get("port")
    parts = []
    family = spec.get("family")
    if family:
        parts.append([(str(family), None)])
    if addr is not None or port is not None:
        where = [("to:", None)]
        if addr is not None:
            where += value_segments(addr)
            if port is not None:
                where.append((":", None))
        if port is not None:
            where += value_segments(port)
        parts.append(where)
    flags = target_flags(spec)
    if flags:
        parts.append([(",".join(flags), None)])
    return with_rest(joined(parts), spec,
                     "family", "addr", "port", "flags")


def queue_extra(spec):
    """The tuning of a queue statement, in nft's own order and wording."""
    if not isinstance(spec, dict):
        return []
    parts = []
    flags = target_flags(spec)
    if flags:
        parts.append([("flags", None), (" ", None), (",".join(flags), None)])
    if spec.get("num") is not None:
        # A queue can be picked per packet, by a numgen or a map, so the
        # destination is not always a number.
        parts.append([("to", None), (" ", None),
                      *value_segments(spec["num"])])
    return with_rest(joined(parts), spec, "flags", "num")


def split_target(kind, spec):
    """Return (target, extra segments) for the statement the TARGET column got.

    Usually one that ends the rule; a PACKET_ACTIONS statement where the rule
    ended without one. The last line covers both the NAT targets and those,
    because `to:addr:port` is how all of them name a destination.
    """
    if kind in VERDICTS:
        return kind.upper(), []
    if kind in ("jump", "goto"):
        # nft leaves this null when the rule names no chain, and a jump to
        # nowhere is not something the column can say.
        chain = spec.get("target") if isinstance(spec, dict) else None
        return (chain, []) if chain else ("", [])
    if kind == "reject":
        return "REJECT", reject_extra(spec)
    if kind == "queue":
        return "QUEUE", queue_extra(spec)
    return kind.upper(), nat_extra(spec)


def format_pairs(spec, skip=()):
    """The named parts of a statement, in the order nft handed them over.

    The key is the statement's own word for the part rather than anything the
    rule is about, so it is a LABEL: what a reader came for is the value.
    """
    if spec is None:
        return []
    if not isinstance(spec, dict):
        return [value_segments(spec)]
    return [joined([label(k), value_segments(v)])
            for k, v in spec.items() if k not in skip]


def format_generic(kind, spec):
    """A statement nobody wrote a formatter for, laid out as nft named it.

    Every statement is a name over a bag of named parts, so `foo a 1 b 2` reads
    even when it is not the phrasing nft would have chosen. This is what keeps
    the old failure mode from coming back: a statement nfrtop does not
    recognize used to swallow the verdict along with it, and now it cannot,
    because nothing here has to be recognized to be shown.

    nft's own name for the statement stands where a field name would, so it is
    left plain; the keys under it are labels like any other statement's.
    """
    return joined([[(kind, None)], *format_pairs(spec)])


def with_rest(segments, spec, *used):
    """Whatever a formatter said, plus the keys it did not account for.

    A formatter knows the shape nft documents today. A key added by a later nft
    would otherwise be read, understood as nothing in particular, and dropped -
    which is the one thing a viewer of a firewall must not do quietly. Naming
    it in the generic form leaves it looking odd rather than not looking.
    """
    if not isinstance(spec, dict):
        return segments
    return joined([segments, *format_pairs(spec, skip=used)])


def symbolic_field(left):
    """Whether what is matched against `left` is spelled in nft's own words.

    Read off the structure nft sent rather than the text it produced. The
    string `established` says nothing about itself; only the field it is being
    held against says it is a connection state and not, say, the name of a set
    someone called `established`.

    A mask is looked through rather than counted as a field of its own. nft
    sends `tcp flags & (syn|rst) == syn` as an `&` over the field and the bits
    being kept, and what the whole of that is about is still the field: the
    `syn` on the right is a flag name, and so are the `syn` and `rst` inside
    the mask.
    """
    if not isinstance(left, dict) or len(left) != 1:
        return False
    kind, spec = next(iter(left.items()))
    if kind in BINARY_OPS and isinstance(spec, list) and spec:
        return symbolic_field(spec[0])
    if not isinstance(spec, dict):
        return False
    if kind == "ct":
        return (kind, spec.get("key")) in SYMBOLIC_FIELDS
    if kind == "payload":
        return (spec.get("protocol"), spec.get("field")) in SYMBOLIC_FIELDS
    return False


def format_match(spec):
    """A match, in nft's word order: what is compared, how, and to what.

    The equality is left unwritten, so `iifname "lo"` reads as it was typed.
    nft does print it in one case, where the left side is masked, and that case
    is the one the left side names for itself: an operator over operands is a
    mask, and a field is not. Written out there and nowhere else, the '==' of
    `tcp flags & (syn | rst | ack) == syn` puts the two halves of the match
    back on either side of something, where run together they were four words
    in a row with nothing to say the last of them was what the rest were held
    against.

    An ordering comparison keeps its operator, because there it is the point.

    Both sides are the rule's own words - the left is the name of what the rule
    is about and the right is what it is held to - so neither is dimmed for
    being one side of a match. The words inside them are still QUIET_WORDS' to
    judge, which is how the `type` of `icmp type echo-request` fades while the
    `dport` beside it does not: that is a decision about the word, made where
    the word is written, and not about the side it landed on.

    The left is also what says whether the right is one of nft's own words.
    That is asked here rather than further down because here is the last place
    that can see both sides at once. The answer goes to both sides: where the
    left is a masked field, the bits of the mask are spelled in the same words
    the right side is, and `tcp flags & (syn|rst) == syn` has three flag names
    in it rather than one.
    """
    if not isinstance(spec, dict):
        return format_generic("match", spec)
    field = spec.get("left")
    plain = SYMBOL if symbolic_field(field) else None
    left = value_segments(field, plain)
    right = value_segments(spec.get("right"), plain)
    op = spec.get("op")
    if op in ("==", None) and is_binop(field):
        parts = [left, [("==", None)]]
    elif op in ("==", "in", None):
        parts = [left]
    else:
        parts = [left, [(str(op), None)]]
    return with_rest(joined([*parts, right]), spec, "op", "left", "right")


def format_counter(spec):
    """What a counter statement has left to say once its columns are filled.

    A named counter is a reference to a counter kept elsewhere, and that
    reference is the only thing about it this rule shows.

    The anonymous counter that PKTS and BYTES were taken from never reaches
    here: split_rule() lifts it, as it does any statement a column took. One
    that does reach here is a second counter in the same rule, counting what
    got as far as its own position, and it is spelled out rather than dropped.
    """
    if isinstance(spec, str):
        return joined([[("counter", None)], label("name"),
                       [(f'"{spec}"', None)]])
    return format_generic("counter", spec)


def format_log(spec):
    """`log prefix "drop: " level info`, with the prefix quoted as nft has it."""
    if not isinstance(spec, dict):
        return format_generic("log", spec)
    parts = [[("log", None)]]
    if "prefix" in spec:
        parts.append(joined([label("prefix"),
                             [('"{}"'.format(spec["prefix"]), None)]]))
    parts.extend(format_pairs(spec, skip=("prefix",)))
    return joined(parts)


def format_limit(spec):
    """`limit rate 10/second burst 5 packets`, as nft writes a rate limit.

    Anything beyond the parts nft is known to spell this way is appended in the
    generic form rather than dropped, so a key added by a later nft shows up
    looking odd instead of not showing up at all.
    """
    if not isinstance(spec, dict):
        return format_generic("limit", spec)
    parts = [[("limit", None)]]
    if spec.get("inv"):
        parts.append(label("over"))
    if spec.get("rate") is not None:
        # The period hangs off the rate with a slash, the way nft writes it.
        rate = joined([label("rate"), value_segments(spec["rate"]),
                       label(spec["rate_unit"])
                       if spec.get("rate_unit") is not None else []])
        if spec.get("per"):
            rate += [("/", None), (str(spec["per"]), None)]
        parts.append(rate)
    if spec.get("burst") is not None:
        parts.append(joined([label("burst"), value_segments(spec["burst"]),
                             label(spec.get("burst_unit", "packets"))]))
    parts.extend(format_pairs(spec, skip=LIMIT_KEYS))
    return joined(parts)


def format_xt(spec):
    """An iptables extension, named as far as nft is able to name it.

    nft says outright that it cannot render these back into iptables' own
    syntax; the man page calls the loss unavoidable. What it does hand over is
    the kind of extension and its name, and `xt match comment` says more about
    what is in the rule than a bare `xt` does.
    """
    if not isinstance(spec, dict):
        return [("xt", None)]
    parts = ["xt"]
    for part in (spec.get("type"), spec.get("name")):
        if part:
            parts.append(str(part))
    return with_rest([(" ".join(parts), None)], spec, "type", "name")


def format_vmap(spec):
    """`iifname vmap { eth0 : jump wan }` - a match and a verdict in one.

    This is why vmap has no TARGET of its own: the verdict is per lookup, so
    there is no single one to name in the column.
    """
    if not isinstance(spec, dict):
        return format_generic("vmap", spec)
    return with_rest(joined([value_segments(spec.get("key")),
                             [("vmap", None)],
                             format_map_data(spec.get("data"))]),
                     spec, "key", "data")


def statement_segments(stmt):
    """One statement, in pieces, each knowing what kind of thing it is.

    Which pieces are which is the formatter's to say, because only what built
    the text knows where a word it wrote itself ends and the ruleset's own
    content begins. Looking for the boundary again afterwards would be
    guesswork over ruleset text, which is how a comment reading `rate 10` ends
    up drawn as though nfrtop had written it.
    """
    if not isinstance(stmt, dict) or len(stmt) != 1:
        return value_segments(stmt)
    kind, spec = next(iter(stmt.items()))
    if kind == "match":
        return format_match(spec)
    if kind == "counter":
        return format_counter(spec)
    if kind == "log":
        return format_log(spec)
    if kind == "limit":
        return format_limit(spec)
    if kind == "vmap":
        return format_vmap(spec)
    if kind in ("jump", "goto"):
        chain = spec.get("target") if isinstance(spec, dict) else None
        return [(f"{kind} {chain}" if chain else kind, None)]
    if kind in VERDICTS:
        return [(kind, None)]
    if kind == "xt":
        return format_xt(spec)
    return format_generic(kind, spec)


def format_statement(stmt):
    """One statement of a rule, in as close to nft's own words as can be had."""
    return "".join(text for text, _ in statement_segments(stmt))


def matches(expr):
    """The match statements of a rule, with their place in it."""
    for i, stmt in enumerate(expr):
        m = stmt.get("match") if isinstance(stmt, dict) else None
        if isinstance(m, dict):
            yield i, m


def split_rule(expr, comment=""):
    """Sort a rule's statements into the columns and the OPTIONS that remain.

    A statement that a column has taken over is not repeated in OPTIONS, and
    everything else is spelled out there, so no part of a rule can go missing
    for want of somewhere to put it.
    """
    fields = dict.fromkeys(
        ("target", "proto", "iif", "oif", "saddr", "daddr", "comment"), "")
    lifted = set()
    extra = []

    for i, m in matches(expr):
        op = m.get("op")
        column = match_column(m.get("left"))
        # The first match wins the column, as with a rule that narrows the same
        # field twice; the rest of it is still spelled out in OPTIONS.
        if op not in VALUE_OPS or not column or fields[column]:
            continue
        value = match_value(m.get("right"))
        if value is None:
            continue
        if column == "proto":
            value = proto_name(value)
        fields[column] = f"!={value}" if op == "!=" else str(value)
        lifted.add(i)

    if not fields["proto"]:
        for _, m in matches(expr):
            hint = proto_hint(m.get("left"))
            if hint:
                fields["proto"] = hint
                break

    target_at = fallback_at = None
    for i, stmt in enumerate(expr):
        if not isinstance(stmt, dict) or len(stmt) != 1:
            continue
        kind = next(iter(stmt))
        if kind in TARGET_KEYS:
            # A verdict ends the rule, so there is only ever one to find.
            target_at = i
            break
        # The first one, because it is the first thing done to the packet.
        if fallback_at is None and kind in PACKET_ACTIONS:
            fallback_at = i

    # Nothing ended the rule, so what was done to the packet on the way through
    # is the most the column can say about where the packet went.
    if target_at is None:
        target_at = fallback_at
    if target_at is not None:
        kind, spec = next(iter(expr[target_at].items()))
        fields["target"], extra = split_target(kind, spec)
        lifted.add(target_at)

    counter = counter_index(expr)
    if counter is not None:
        # PKTS and BYTES are this one, and a column does not say its statement
        # twice. Any further counter is left for OPTIONS to spell out.
        lifted.add(counter)

    shown = [statement_segments(s) for i, s in enumerate(expr)
             if i not in lifted]
    # The verdict's own detail goes last of the statements, where nft puts it.
    fields["option_parts"] = joined([*shown, extra])
    # The comment is an attribute of the rule rather than a statement in it, so
    # it is kept separate here and printed last, where nft prints it.
    fields["comment"] = comment
    return fields


def parse_ruleset(text):
    """Build a Ruleset from the output of `nft -j list ruleset`.

    The top level is a list of one-key objects. Only the first, metainfo, is
    documented to sit where it does, so this dispatches on the key and never on
    the position. It also names the two kinds it wants rather than skipping the
    ones it knows: a named counter and a rule that counts are both spelled
    'counter', and a kind added by some later nft must not become a phantom
    rule.

    The walk is in two passes because the order of the kinds is not fixed
    either - 1.1.7 lists chains before rules, 0.9.6 puts a set between them -
    so a rule's chain, and with it the hook that colors its row, may not be
    known yet when the rule goes by.
    """
    try:
        doc = json.loads(text)
    except ValueError:
        raise RuntimeError(NOT_JSON)
    except RecursionError:
        # Nesting deeper than the interpreter will walk. Not something nft
        # produces, but this is a parser and it should say so rather than end
        # the session in a traceback.
        raise RuntimeError("nft output is nested too deeply to read")

    top = doc.get("nftables") if isinstance(doc, dict) else None
    if not isinstance(top, list):
        raise RuntimeError(NOT_JSON)

    result = Ruleset()
    listed = []
    for item in top:
        if not isinstance(item, dict):
            continue
        for kind, obj in item.items():
            if not isinstance(obj, dict):
                continue
            if kind == "chain":
                # Only a base chain has a hook, and nft fills its policy in even
                # when the ruleset left it at the default, so there is nothing
                # to infer here. A chain that is neither keeps both empty.
                hook = obj.get("hook", "")
                result.chains[(obj.get("family"), obj.get("table"),
                               obj.get("name"))] = ChainInfo(
                    hook=hook,
                    policy=obj.get("policy", "accept") if hook else "",
                )
            elif kind == "rule":
                listed.append(obj)

    numbers = {}
    for order, obj in enumerate(listed):
        chain_key = (obj.get("family"), obj.get("table"), obj.get("chain"))
        # NUM is the rule's place in its chain. nft lists a chain's rules in
        # order, whatever it does with the kinds around them.
        numbers[chain_key] = numbers.get(chain_key, 0) + 1
        expr = obj.get("expr", [])
        # Everything past here walks the statements and does arithmetic on the
        # counters, so this is the boundary at which the shape has to be true.
        # nft always gets it right; a truncated pipe or something else wearing
        # nft's name does not, and the difference should read as a message and
        # not as a traceback from the middle of the render.
        if not isinstance(expr, list):
            raise RuntimeError("nft rule has no list of statements")
        packets, nbytes = rule_counter(expr)
        if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0
                   for n in (packets, nbytes) if n is not None):
            raise RuntimeError("nft counter is not a count")
        # Taking the rule apart and spelling it out walks the same structure
        # the checks above only looked at the top of, so the conversion covers
        # both: a rule too deep to walk is a message, not a traceback.
        try:
            text = rule_body(expr)
            fields = split_rule(expr, obj.get("comment", ""))
        except RecursionError:
            raise RuntimeError("nft rule is nested too deeply to read")
        except (TypeError, ValueError):
            raise RuntimeError("nft rule is not a shape this can read")
        result.rules.append(Rule(
            family=chain_key[0],
            table=chain_key[1],
            chain=chain_key[2],
            handle=obj.get("handle"),
            packets=packets,
            bytes=nbytes,
            text=text,
            order=order,
            num=numbers[chain_key],
            hook=result.chains.get(chain_key, ChainInfo()).hook,
            **fields,
        ))

    return result


def human_count(n):
    if n is None:
        return "-"
    units = ("", "K", "M", "G", "T", "P")
    x = float(n)
    for u in units:
        # 999.95, not 1000: the mantissa must stay under 1000 once rounded.
        if abs(x) < 999.95 or u == units[-1]:
            if u == "":
                return str(int(x))
            # Past the last unit the mantissa is unbounded, so drop the decimal
            # to keep the width predictable.
            return f"{x:.1f}{u}" if abs(x) < 999.95 else f"{x:.0f}{u}"
        x /= 1000


def human_bytes(n):
    if n is None:
        return "-"
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    x = float(n)
    for u in units:
        if abs(x) < 1023.95 or u == units[-1]:
            if u == "B":
                return f"{int(x)}B"
            return f"{x:.1f}{u}" if abs(x) < 999.95 else f"{x:.0f}{u}"
        x /= 1024


def human_rate(n):
    if n is None:
        return "-"
    return human_bytes(n) + "/s"


def human_bitrate(n):
    if n is None:
        return "-"
    # Bit rates are conventionally decimal, unlike the binary byte prefixes.
    return human_count(n * 8) + "b/s"


def human_pps(n):
    if n is None:
        return "-"
    if abs(n) < 999.95:
        return f"{n:.1f}"
    return human_count(round(n))


def parse_rate(text, bits):
    """Parse a threshold such as 200, 1.5k or 10M into bytes per second."""
    m = RATE_RE.match(text.strip())
    if not m:
        raise ValueError(f"invalid rate: {text!r}")
    value = float(m.group(1))
    # Match the prefixes used for display: decimal for bits, binary for bytes.
    value *= (1000 if bits else 1024) ** " kmgt".index(m.group(2).lower() or " ")
    value = value / 8 if bits else value
    # Enough digits and float() hands back inf, which would silently hide the
    # whole ruleset rather than filter it.
    if not math.isfinite(value):
        raise ValueError(f"rate out of range: {text!r}")
    return value


# What says a value was cut short. One column wide either way, so the layout
# does not care which of the two is in use; main() settles it against stdout.
ELLIPSIS = "…"

# The encoding stdout cannot carry everything in, or None where it can. main()
# settles it too; until then nothing is escaped for want of a codec, which is
# what a caller from outside the program - a test - should get.
ENCODING = None


def usable_ellipsis(stream):
    """`…` where stdout can carry it, `.` where it cannot.

    An ASCII stdout - a minimal system with no UTF-8 locale, or an explicit
    PYTHONIOENCODING - would otherwise turn the first truncated row into a
    UnicodeEncodeError, and a viewer that dies on a narrow terminal is worse
    than one that marks the cut with a plainer character.
    """
    try:
        ELLIPSIS.encode(stream.encoding or "ascii")
    except (UnicodeEncodeError, LookupError, AttributeError):
        return "."
    return ELLIPSIS


def limited_encoding(stream):
    """A stream's encoding if it cannot carry every character, else None.

    A UTF codec carries anything there is, so there is nothing to ask about it
    per character. Any other one has to be asked, because what it cannot encode
    is written as an escape and an escape is wider than what it replaces.
    """
    encoding = getattr(stream, "encoding", None) or "ascii"
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        return encoding
    return None if name.startswith("utf") else encoding


def escaped(ch):
    """A character spelled so that it is only ever text."""
    return f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}"


def printable(ch):
    """Whether a character reaches the screen as itself and as one thing."""
    if unicodedata.category(ch) in ("Cc", "Cf"):
        return False
    if ENCODING is None:
        return True
    try:
        ch.encode(ENCODING)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def safe(s):
    """A string with nothing left in it the terminal would read as a command.

    A rule's comment, a set element, an interface name: all of it comes from
    the ruleset, and nothing stops one holding an ESC. Left alone it would home
    the cursor, clear the screen or set the window title from inside a cell,
    and --color never would not stop it - the sequence is in the data, not in
    the styling. A newline in a comment would likewise put one rule on two
    lines. Spelling them out costs nothing and leaves nothing executable.

    Cf goes with Cc: a bidi override reorders what follows it on screen, which
    is a different way for a cell to lie about what a rule says.

    A character stdout cannot encode is spelled out here too, and for the same
    reason the widths need it done here: written straight out it would be
    turned into an escape by the codec, after every column had been sized for
    the one character it used to be.
    """
    return "".join(ch if printable(ch) else escaped(ch) for ch in s)


def cell_width(ch):
    """How many terminal cells one character occupies."""
    if unicodedata.combining(ch):
        # An accent lands on the character before it rather than beside it.
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def display_width(s):
    """How wide a string prints, which is not the same as how long it is.

    len() counts characters, and a column sized by it puts a CJK comment two
    cells over its own edge for every character in it. The table is a grid of
    cells, so cells are what the widths have to be counted in.
    """
    return sum(cell_width(ch) for ch in s)


def clip(s, width):
    """The longest prefix of an already-escaped string that fits `width`.

    A wide character is not split down the middle to reach the width: it is
    two cells or it is neither.
    """
    out, used = [], 0
    for ch in s:
        w = cell_width(ch)
        if used + w > width:
            break
        out.append(ch)
        used += w
    return "".join(out)


def truncate(s, width):
    """Cut a string to fit `width` cells, marking it where it was cut.

    Everything on screen passes through here, so this is also where whatever
    the ruleset had to say stops being able to say it to the terminal.
    """
    s = safe(s)
    if width <= 0:
        return ""
    if display_width(s) <= width:
        return s
    if width == 1:
        return ELLIPSIS
    # The ellipsis takes the last cell.
    return clip(s, width - 1) + ELLIPSIS


def truncate_segments(segments, width):
    """Cut a sequence of (text, code) to fit `width` cells, marking the cut.

    A segment is as far as a color run may reach, so each is escaped and
    measured on its own rather than after being joined. Mixing a color code
    into the text and then calling truncate() on the result would not work:
    safe() would spell the code out as `\\x1b[2m` and the screen would show it
    instead of obeying it. Color goes on afterwards, in paint_segments().

    The plain text this produces is the same, cell for cell, as running
    truncate() over the joined-up string, so color cannot move a column edge.
    """
    parts = [(safe(text), code) for text, code in segments]
    parts = [(text, code) for text, code in parts if text]

    # Ahead of the fits-already case: a zero-width character costs nothing to
    # measure but is still something, and a column with no cells at all can
    # hold nothing whatever, not even what takes up no room.
    if width <= 0:
        return []
    if sum(display_width(text) for text, _ in parts) <= width:
        return parts
    if width == 1:
        return [(ELLIPSIS, None)]

    # The ellipsis is the frame saying there was more, not the ruleset saying
    # anything, so it stays uncolored.
    out, used = [], 0
    for text, code in parts:
        fitted = clip(text, width - 1 - used)
        if fitted:
            out.append((fitted, code))
            used += display_width(fitted)
        if fitted != text:
            # Stopping here rather than trying the next segment is what keeps
            # the cut in the same place truncate() would put it: a segment cut
            # short by a wide character can leave a cell free, and filling it
            # from the segment after would run past that.
            break
    out.append((ELLIPSIS, None))
    return out


def pad(s, width, align):
    """Fill a cell out to its width, counting cells rather than characters."""
    gap = width - display_width(s)
    if gap <= 0:
        return s
    return s + " " * gap if align == "<" else " " * gap + s


def update_rates(rules, previous, elapsed):
    if elapsed <= 0:
        return
    for r in rules:
        old = previous.get(r.key)
        # The rule is a fresh object every sample, so anything that has to
        # outlive a sample is carried across here.
        if old:
            r.was_active = old.was_active

        if r.packets is None or r.bytes is None:
            continue
        if not old or old.packets is None or old.bytes is None:
            r.pps = r.bps = 0.0
            continue

        dp = r.packets - old.packets
        db = r.bytes - old.bytes

        # Counters may be reset or the ruleset may be replaced.
        if dp < 0 or db < 0:
            r.pps = r.bps = 0.0
        else:
            r.pps = dp / elapsed
            r.bps = db / elapsed
            if dp or db:
                r.was_active = True


def matches_filters(r, args):
    if args.family and r.family != args.family:
        return False
    if args.table and r.table != args.table:
        return False
    if args.chain and r.chain != args.chain:
        return False
    if args.counted_only and r.packets is None:
        return False
    # A threshold of 0 is a threshold: it still asks for rules that can report
    # a rate, so it is told apart from --min-rate having gone unasked for.
    if args.min_rate_bps is not None:
        # A rule with no counter can never report a rate.
        if r.packets is None:
            return False
        # Keep counted rules until the first interval has been measured.
        if r.bps is not None and r.bps < args.min_rate_bps:
            return False
    return True


@dataclass
class Column:
    title: str
    align: str
    minw: int          # the floor this column may be shrunk to
    prefw: int         # the width it takes when there is room
    fixed: bool        # take prefw regardless of the values on screen
    get: object        # rule -> cell text
    style: object = None   # rule -> ANSI code, or None for no color
    width: int = 0     # resolved by layout()


def direction_color(hook):
    """Green for packets coming in, red for packets going out, yellow between."""
    if not hook:
        # A user-defined chain is reached by jump, so it has no direction.
        return None
    if hook in INBOUND_HOOKS:
        return GREEN
    if hook in OUTBOUND_HOOKS:
        return RED
    return YELLOW


def faint_if_empty(get, code=None):
    """Paint a matcher that is set, and fade the wildcard that stands for any."""
    return lambda r: code if get(r) else FAINT


def target_color(r):
    if not r.target:
        return FAINT
    # An unknown target is the chain a jump or goto names, not a verdict, so
    # it is left in the default color.
    return TARGET_COLORS.get(r.target)


def directional(get):
    """Color a figure by the direction of its chain.

    A zero fades away, unless the rule has already carried traffic during this
    session: a rule that has gone quiet is worth noticing, so it keeps the
    terminal's own foreground rather than being dimmed with the rules that have
    never matched at all.
    """
    def style(r):
        if get(r):
            return direction_color(r.hook)
        return None if r.was_active else FAINT
    return style


# A fixed column always takes its preferred width, sized for the widest value
# its formatter can produce. Sizing those to the values currently on screen
# would shift the whole table sideways whenever a counter crossed a unit
# boundary.
def base_columns(bits):
    rate = human_bitrate if bits else human_rate
    return [
        # NUM is the position within the chain, as iptables --line-numbers
        # reports it. HNDL is nft's own identity for the rule and is what
        # `nft delete rule ... handle N` expects.
        Column("NUM", ">", 3, 4, False, lambda r: str(r.num),
               lambda r: BLUE),
        Column("HNDL", ">", 4, 6, False, lambda r: str(r.handle),
               lambda r: BLUE),
        Column("PKTS", ">", 5, 6, True, lambda r: human_count(r.packets),
               directional(lambda r: r.packets)),
        Column("BYTES", ">", 6, 8, True, lambda r: human_bytes(r.bytes),
               directional(lambda r: r.bytes)),
        Column("PPS", ">", 5, 6, True, lambda r: human_pps(r.pps),
               directional(lambda r: r.pps)),
        Column("RATE", ">", 7, 10, True, lambda r: rate(r.bps),
               directional(lambda r: r.bps)),
        Column("TARGET", "<", 6, 14, False, lambda r: r.target or "-",
               target_color),
        Column("PROT", "<", 4, 8, False, lambda r: r.proto or ANY,
               faint_if_empty(lambda r: r.proto)),
        Column("IN", "<", 3, 12, False, lambda r: r.iif or ANY,
               faint_if_empty(lambda r: r.iif, YELLOW)),
        Column("OUT", "<", 3, 12, False, lambda r: r.oif or ANY,
               faint_if_empty(lambda r: r.oif, YELLOW)),
        # Wide enough for any IPv4 CIDR and for the short IPv6 prefixes that
        # rules use in practice. A longer address or a set is truncated rather
        # than allowed to crowd out OPTIONS; the full text is in `nft list`.
        Column("SOURCE", "<", 7, 24, False, lambda r: r.saddr or ANY,
               faint_if_empty(lambda r: r.saddr)),
        Column("DEST", "<", 7, 24, False, lambda r: r.daddr or ANY,
               faint_if_empty(lambda r: r.daddr)),
    ]


def location_columns():
    return [
        Column("FAM", "<", 3, 5, False, lambda r: r.family),
        Column("CHAIN", "<", 8, 26, False, lambda r: f"{r.table}/{r.chain}",
               lambda r: direction_color(r.hook)),
    ]


# Where the room has to come from once every column sits at its floor, most
# expendable first. NUM, TARGET, FAM and CHAIN are not here: they are what says
# which rule a row is about, and a row that cannot say that is not worth
# keeping the rest of.
DROP_ORDER = ("OUT", "IN", "DEST", "SOURCE", "PROT", "PPS", "BYTES", "HNDL",
              "RATE", "PKTS")


def layout(rules, width, view):
    """Size every column to its content, then shrink, then drop, to fit."""
    columns = base_columns(view.bits)
    if not view.grouped:
        columns = location_columns() + columns

    for c in columns:
        want = c.prefw
        if not c.fixed:
            want = min(c.prefw, max((display_width(safe(c.get(r)))
                                     for r in rules), default=0))
        c.width = max(display_width(c.title), c.minw, want)

    # Every column is followed by a single space, including the last one.
    # A column already at its floor has nothing left to give, so on a terminal
    # too narrow to hold them all, one has to go: a dropped column is a visible
    # absence, while a row wider than the screen wraps, and a wrapped table has
    # stopped being a table.
    def floor():
        return sum(c.minw + 1 for c in columns) + OPTIONS_MIN_WIDTH

    dropped = []
    for title in DROP_ORDER:
        if floor() <= width:
            break
        for i, c in enumerate(columns):
            if c.title == title:
                dropped.append(columns.pop(i))
                break

    # OPTIONS_MIN_WIDTH is the room aimed at for the last column, not a
    # guarantee: OPTIONS gives way first, and the columns follow it down.
    used = sum(c.width for c in columns) + len(columns)
    while used + OPTIONS_MIN_WIDTH > width:
        widest = max(columns, key=lambda c: c.width - c.minw)
        if widest.width - widest.minw <= 0:
            break
        widest.width -= 1
        used -= 1

    return columns, max(0, width - used), dropped


def dropped_segments(dropped, r):
    """What a rule said in the columns that did not fit, ready for OPTIONS.

    A match lifted into a column is not repeated in OPTIONS, so a column that
    goes takes the match with it unless it is handed back. A wildcard is handed
    back as nothing: it says the rule does not narrow that field, which is also
    what the absence of the column says.

    The title is faint because it is nfrtop's word for where the value came
    from rather than anything the rule says; the value beside it is the rule.
    """
    parts = []
    for c in dropped:
        value = c.get(r)
        if value and value not in (ANY, "-"):
            parts.append([(c.title, FAINT), (" ", None), (value, None)])
    return joined(parts)


def paint(text, code, color):
    if not color or not code:
        return text
    return f"{code}{text}{RESET}"


def paint_segments(parts, color):
    """Color each segment of an already-truncated run and join it back up.

    The separators are segments of their own, so no color run ends on a space
    and rstrip_row() has nothing tucked inside one to find.
    """
    return "".join(paint(text, code, color) for text, code in parts)


def format_row(columns, options_width, cells, options, width,
               styles=None, color=False):
    """Pad first, then color, so escape codes never affect column widths."""
    parts, used = [], 0
    for i, c in enumerate(columns):
        # A terminal narrower than even the columns layout() managed to keep.
        # The widths are settled for the whole frame before any row is built,
        # so every row and the header give up at the same column.
        if used + c.width > width:
            break
        parts.append(paint(pad(truncate(cells[i], c.width), c.width, c.align),
                           styles[i] if styles else None, color))
        used += c.width + 1
    if used < width:
        parts.append(paint_segments(
            truncate_segments(options, min(options_width, width - used)),
            color))
    return rstrip_row(" ".join(parts))


def rstrip_row(s):
    """Drop trailing padding, including padding tucked inside a color run."""
    s = s.rstrip()
    if s.endswith(RESET):
        body = s[:-len(RESET)].rstrip()
        s = body + RESET
    return s


def chain_header(rule, chains):
    info = chains.get(rule.chain_key)
    bits = [f"{rule.family} {rule.table}"]
    if info and info.hook:
        bits.append(f"hook {info.hook}")
    if info and info.policy:
        bits.append(f"policy {info.policy}")
    return f"Chain {rule.chain} ({', '.join(bits)})"


def render_lines(rules, chains, view, interval=None, hidden=0, height=None):
    """Build the whole frame as a list of lines, one per screen row.

    `height` is the number of rows the frame may occupy, or None for as many as
    it takes. A live frame taller than the terminal scrolls, and scrolling
    takes the header and the first rules off the top, which is the opposite of
    what redrawing in place is for; a frame written to a pipe is a document and
    is never cut. What does not fit is counted in the footer.
    """
    width = shutil.get_terminal_size((160, 40)).columns
    columns, options_width, dropped = layout(rules, width, view)

    titles = [c.title for c in columns]
    header = format_row(columns, options_width, titles,
                        [("OPTIONS", None)], width)
    head = [paint(header, BOLD, view.color),
            "-" * min(width, display_width(header))]

    # Each line is paired with whether it is a rule, so that cutting the frame
    # short can say how many rules went with it.
    body = []
    current_chain = None
    for r in rules:
        if view.grouped and r.chain_key != current_chain:
            current_chain = r.chain_key
            code = BOLD + (direction_color(r.hook) or "")
            body.append(("", False))
            body.append((paint(truncate(chain_header(r, chains), width),
                               code, view.color), False))
        cells = [c.get(r) for c in columns]
        styles = [c.style(r) if c.style else None for c in columns]
        # The comment goes last, where nft prints it, and faint: it is the one
        # part of a rule that says nothing about what the rule does.
        options = joined([dropped_segments(dropped, r),
                          [(text, OPTION_COLORS.get(role))
                           for text, role in r.option_parts],
                          [(f"/* {r.comment} */", FAINT)] if r.comment else []])
        body.append((format_row(columns, options_width, cells, options,
                                width, styles, view.color), True))

    omitted = 0
    if height is not None:
        # Two lines for the footer, and whatever the header took.
        room = max(0, height - len(head) - 2)
        if len(body) > room:
            omitted = sum(1 for _, is_rule in body[room:] if is_rule)
            body = body[:room]
            # A chain heading with nothing under it names a chain the frame no
            # longer shows.
            while body and not body[-1][1]:
                body.pop()

    counted = sum(1 for r in rules if r.packets is not None)
    suffix = f"{len(rules)} rules"
    if omitted:
        # Ahead of everything the footer says about the rules that are on
        # screen: this is the one part of it that explains what is not, and a
        # narrow terminal truncates the footer from the right like any row.
        suffix += f" ({omitted} below the screen)"
    suffix += f", {counted} with anonymous counters"
    if hidden:
        suffix += f", {hidden} hidden by filters"
    if interval is not None:
        # The interval is whatever was asked for, so print the digits it was
        # given rather than padding every value out to a fixed precision.
        suffix += f" | interval {interval:g}s"
    lines = [*head, *(line for line, _ in body), "", truncate(suffix, width)]
    # A height too small even for a header and a footer still gets no more
    # rows than it asked for; what is left is the top of the frame.
    return lines if height is None else lines[:height]


def write_frame(lines, live):
    """Put a frame on screen, overwriting the previous one in place.

    Blanking the screen and then filling it leaves the terminal showing nothing
    for as long as the frame takes to arrive, and that empty moment is what
    reads as a flicker. Homing the cursor and erasing each row as it is
    rewritten never shows an empty screen; the trailing erase drops whatever the
    previous, longer frame left below. The synchronized-update mode then asks
    the terminal to hold its repaint until the whole frame has landed.

    The frame goes out in a single write. Written line by line, a terminal
    repaints line by line, and the fill is visible - especially over ssh.

    Every line either ends in RESET or carries no styling at all, so the erases
    always run with the default background.
    """
    if not live:
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()
        return
    # Every line is followed by the erase, but only the lines between them are
    # followed by a newline: after a frame exactly as tall as the terminal, a
    # last newline would scroll the screen and take the header off the top of
    # it - which is what fitting the frame to the screen was for.
    body = (CLEAR_EOL + "\n").join(lines) + CLEAR_EOL
    sys.stdout.write(SYNC_BEGIN + HOME + body + CLEAR_EOS + SYNC_END)
    sys.stdout.flush()


def next_deadline(deadline, interval):
    """When to draw next, which is never a time that has already passed.

    A slow nft - or one that took the whole timeout to not answer - leaves the
    deadline behind the clock. Stepping it forward one interval at a time would
    then spend the arrears redrawing as fast as nft can be started, which is the
    opposite of what an interval is for. The missed cycles are given up.
    """
    return max(deadline + interval, time.monotonic())


def frame_height(live):
    """How many rows a frame may take, or None where it may take as many.

    A frame written to a pipe is a document and is never cut short. On a
    terminal it is a screen, and a screen that scrolls has taken the header and
    the first rules off the top - which is the opposite of what redrawing in
    place is for.
    """
    return shutil.get_terminal_size((160, 40)).lines if live else None


def want_color(mode):
    # An explicit --color always wins; otherwise honor the NO_COLOR convention.
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def sort_rules(rules, mode):
    if mode == "rate":
        rules.sort(key=lambda r: (r.bps is not None, r.bps or 0), reverse=True)
    elif mode == "packets":
        rules.sort(key=lambda r: (r.packets is not None, r.packets or 0), reverse=True)
    elif mode == "bytes":
        rules.sort(key=lambda r: (r.bytes is not None, r.bytes or 0), reverse=True)
    else:
        rules.sort(key=lambda r: r.order)


def main():
    ap = argparse.ArgumentParser(
        description="Live, read-only nftables rule/counter viewer"
    )
    ap.add_argument("-V", "--version", action="version",
                    version=f"nfrtop {__version__}")
    ap.add_argument("-i", "--interval", type=float, default=2.0,
                    help="refresh interval in seconds (default: 2)")
    ap.add_argument("-1", "--once", action="store_true",
                    help="print one snapshot and exit")
    ap.add_argument("-f", "--family", help="show only this family (inet, ip, ip6, ...)")
    ap.add_argument("-t", "--table", help="show only this table")
    ap.add_argument("-c", "--chain", help="show only this chain")
    ap.add_argument("--counted-only", action="store_true",
                    help="hide rules that have no anonymous counter")
    ap.add_argument("--sort", choices=("rule", "rate", "packets", "bytes"),
                    default="rule", help="sort order (default: ruleset order)")
    ap.add_argument("--flat", action="store_true",
                    help="never group by chain; show family and chain columns")
    ap.add_argument("-b", "--bits", action="store_true",
                    help="show the RATE column in bits/s instead of bytes/s "
                         "(the cumulative BYTES counter stays in bytes)")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                    help="colorize output (default: auto, on when stdout is a "
                         "terminal and NO_COLOR is unset)")
    ap.add_argument("--min-rate", metavar="RATE",
                    help="hide rules slower than this, e.g. 200, 1.5k, 10M "
                         "(bytes/s, or bits/s with --bits); rules without a "
                         "counter are hidden too")
    args = ap.parse_args()

    # In-place redrawing only makes sense on a terminal: down a pipe the erase
    # sequences would be text in the output.
    live = not args.once and sys.stdout.isatty()

    if not live:
        # Die on a closed pipe the way every other filter does. Python's
        # default is to turn EPIPE into an exception, and a frame is written in
        # one call, so `nfrtop -1 | head` on a ruleset larger than the pipe
        # buffer would end in a traceback rather than in the silence the reader
        # asked for.
        #
        # Only where there is no terminal to put back: a live session has a
        # cursor to restore, and the default disposition would tear the process
        # down without running the restore. There stdout is a tty and so never
        # the thing that closes, but stderr can be a pipe of its own, and the
        # warning printed when nft fails is enough to meet a closed one.
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    # A rule comment need not be ASCII, and stdout need not be able to carry
    # what it holds: a system with no UTF-8 locale, or a PYTHONIOENCODING that
    # says otherwise, would end the first frame carrying one in a
    # UnicodeEncodeError. Marking what cannot be carried beats dying on it.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, OSError, ValueError):
            pass

    global ELLIPSIS, ENCODING
    ELLIPSIS = usable_ellipsis(sys.stdout)
    # Settled after the reconfigure above and before the first frame, because
    # the widths are counted in what safe() leaves behind and safe() has to
    # know what stdout can carry to leave the right thing behind.
    ENCODING = limited_encoding(sys.stdout)

    # argparse reads 'nan' and 'inf' as floats, and neither is greater than 0
    # in a way the comparison alone can catch: nan fails every comparison, so
    # it would pass the check here and reach time.sleep() as a ValueError.
    if not math.isfinite(args.interval) or args.interval <= 0:
        ap.error("--interval must be a finite number greater than 0")

    args.min_rate_bps = None
    if args.min_rate:
        # A rate is measured between two samples, and --once takes one, so the
        # threshold would have nothing to compare against and would quietly
        # pass every counted rule through. Saying so beats appearing to filter.
        if args.once:
            ap.error("--min-rate needs two samples, so it cannot be used "
                     "with --once")
        try:
            args.min_rate_bps = parse_rate(args.min_rate, args.bits)
        except ValueError as e:
            ap.error(f"--min-rate: {e}")

    if args.once and args.sort == "rate":
        ap.error("--sort rate needs two samples, so it cannot be used "
                 "with --once")

    view = View(
        # Chain grouping only makes sense while rules are in ruleset order.
        grouped=args.sort == "rule" and not args.flat,
        bits=args.bits,
        color=want_color(args.color),
    )

    previous = {}
    previous_at = None
    started = False
    drawn = False

    if live:
        # Before the cursor is hidden, not after: the default disposition would
        # tear the process down without running the restore below, and a signal
        # landing in the gap would leave the terminal with no cursor at all.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    try:
        if live:
            # A cursor jumping across the table on every redraw is itself seen
            # as a flicker. Inside the try, so that whatever ends the session
            # from here on leaves by way of the restore.
            sys.stdout.write(HIDE_CURSOR)

        deadline = time.monotonic()
        while True:
            try:
                ruleset = nft_rules()
            except RuntimeError as e:
                # A transient failure should not end a long-running session.
                if not started:
                    raise
                print(f"nfrtop: {safe(str(e))}", file=sys.stderr)
                deadline = next_deadline(deadline, args.interval)
                time.sleep(max(0.0, deadline - time.monotonic()))
                continue
            started = True
            # After the read, not before it: this is when the counters were
            # taken, and the gap between two of these is what they changed
            # over. Timed before the read instead, the divisor would carry the
            # previous nft's duration in place of this one's.
            now = time.monotonic()

            elapsed = None
            if previous_at is not None:
                elapsed = now - previous_at
                update_rates(ruleset.rules, previous, elapsed)

            rules = [r for r in ruleset.rules if matches_filters(r, args)]
            sort_rules(rules, args.sort)

            hidden = len(ruleset.rules) - len(rules)
            # The footer states the configured cadence. The measured gap is what
            # the rates are divided by, and the two are close but not equal.
            shown = args.interval if elapsed is not None else None
            write_frame(
                render_lines(rules, ruleset.chains, view, shown, hidden,
                             frame_height(live)), live
            )
            drawn = True

            if args.once:
                break

            # Store all current rules, including ones filtered from display.
            previous = {r.key: r for r in ruleset.rules}
            previous_at = now
            # Sleep to the next deadline rather than for the interval: sleeping
            # for it would add however long nft and the render took to every
            # cycle, and the cadence would drift away from the one asked for.
            deadline = next_deadline(deadline, args.interval)
            time.sleep(max(0.0, deadline - time.monotonic()))

    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        # Only reachable while live, where SIGPIPE keeps Python's disposition
        # so that the restore below still runs. stderr is the pipe that can
        # close under a live session, and the nft warning is what meets it.
        pass
    except RuntimeError as e:
        print(f"nfrtop: {safe(str(e))}", file=sys.stderr)
        if "Operation not permitted" in str(e) or "Permission denied" in str(e):
            print("Hint: try running with sudo.", file=sys.stderr)
        return 1
    finally:
        # The cursor belongs to the shell we hid it from, however we leave.
        if live:
            # A live frame ends without a newline, so the cursor is left at the
            # end of the last row - and the shell would start its prompt there,
            # mid-line, over the frame. Ending the line first is what gives the
            # prompt a column of its own. Only once something was drawn: with no
            # frame on screen the cursor is still on the shell's own line, and a
            # newline there would be a blank line before the prompt.
            if drawn:
                sys.stdout.write("\n")
            sys.stdout.write(SHOW_CURSOR)
            sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
