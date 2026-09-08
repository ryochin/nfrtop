# nfrtop - a live, read-only nftables rule viewer

![License](https://img.shields.io/badge/license-MIT-blue.svg)

`nfrtop` reads your nftables ruleset and lays it out as an `iptables -L -n -v` style table: one rule per line, with the matchers you actually look for — interfaces, addresses, protocol, target — lifted into their own columns. Counters come along with it, both the cumulative totals and the rate over the last interval, refreshed in place like `top`.

It never writes. The only thing it runs is `nft -j list ruleset`.

![screenshot](https://raw.githubusercontent.com/ryochin/nfrtop/main/docs/screenshot@2x.png)

## Requirements

- **Linux with nftables.**
- **`nft` built with JSON support.** The `nft -j list ruleset` interface arrived in nftables 0.9.0, but JSON is a build-time option that needs libjansson, so a new enough `nft` is necessary and not sufficient. Distribution packages have carried it for years. There is no fallback to scraping the text output: if your `nft` cannot emit JSON, nfrtop says so and exits rather than failing quietly.
- **Python 3.9 or later.** Standard library only — nothing to `pip install`.
- **Permission to read the ruleset**, which in practice means root.

## Installation

One file, no dependencies. Every release ships `nfrtop.sha256` next to the binary, so fetch both, check the one against the other, and only then put it on your `PATH`:

```sh
base=https://github.com/ryochin/nfrtop/releases/latest/download
curl -fsSL $base/nfrtop -o nfrtop
curl -fsSL $base/nfrtop.sha256 -o nfrtop.sha256
sha256sum -c nfrtop.sha256
sudo install -m 755 nfrtop /usr/local/bin/nfrtop
```

The checksum file names the binary without a path, so run `sha256sum -c` in the directory the download landed in.

For provisioning — Chef, Ansible, or anything else that wants a stable, repeatable target — pin the version instead of tracking `latest` by swapping the first line for:

```sh
version=v0.1.0   # whichever release you are pinning to
base=https://github.com/ryochin/nfrtop/releases/download/$version
```

`nfrtop --version` reports which one is installed.

## Usage

```
usage: nfrtop [-h] [-V] [-i INTERVAL] [-1] [-f FAMILY] [-t TABLE]
              [-c CHAIN] [--counted-only]
              [--sort {rule,rate,packets,bytes}] [--flat] [-b]
              [--color {auto,always,never}] [--min-rate RATE]
```

| Option | |
|---|---|
| `-i`, `--interval SECONDS` | Refresh interval, default 2. |
| `-1`, `--once` | Print one snapshot and exit. |
| `-f`, `--family FAMILY` | Show only this family: `inet`, `ip`, `ip6`, and so on. |
| `-t`, `--table TABLE` | Show only this table. |
| `-c`, `--chain CHAIN` | Show only this chain. |
| `--counted-only` | Hide rules that have no anonymous counter. |
| `--sort {rule,rate,packets,bytes}` | Sort order, default ruleset order. |
| `--flat` | Never group by chain; show family and chain columns instead. |
| `-b`, `--bits` | Show `RATE` in bits/s rather than bytes/s. The cumulative `BYTES` counter stays in bytes. |
| `--color {auto,always,never}` | Colorize. `auto` means on when stdout is a terminal and `NO_COLOR` is unset. |
| `--min-rate RATE` | Hide rules slower than this: `200`, `1.5k`, `10M`. Bytes/s, or bits/s with `--bits`. Rules without a counter are hidden too. |
| `-V`, `--version` | Print the version and exit. |

`--sort rate` and `--min-rate` both measure a change between two samples, so neither can be combined with `--once`; nfrtop says so rather than appearing to work.

Find what is actually moving traffic right now:

```sh
sudo nfrtop --sort rate --counted-only
```

Watch one chain, in bits per second, and drop everything under 1 Mb/s:

```sh
sudo nfrtop -c forward --bits --min-rate 1M
```

Take a single snapshot — for a script, a log, or a pipe:

```sh
sudo nfrtop -1 --flat --color never
```

## Notes

**Reading a row.** `NUM` is the rule's position within its chain, the way `iptables --line-numbers` counts it; `HNDL` is the handle nftables itself gave the rule, and the one `nft delete rule ... handle N` expects. `*` is the iptables wildcard, and means the rule does not narrow that field at all. `OPTIONS` carries whatever the columns did not take: every part of a rule is either lifted into a column or spelled out there, so no part of it goes missing for want of somewhere to put it.

**Rules, not connections.** The name is netfilter **r**ule top. Where the connection-oriented tools in this space rank flows, what is ranked here is the rules of the ruleset itself. (Note that `nftop` is a separate, conntrack-oriented project — different tool, different question.)

**A ruleset reload does not fabricate a rate.** A rate is the change in a counter between two samples, so it depends on knowing that two samples describe the same rule. A handle is not enough to settle that on its own: `nft` reissues a handle to an unrelated rule after a reload, and keying on the handle alone would subtract one rule's counter from another's and report a rate that never happened. nfrtop keys a rule on its body as well as its handle, so a reissued handle attached to different content is recognized as the different rule it is. The counter's values are left out of that key — they are the thing being measured, and a key that moved with them would never match twice. A counter that has gone backwards, which is what a reset looks like, reads as `0` rather than as a negative rate.

A reload usually costs you the rates rather than carrying them across: the reloaded rules are new to nfrtop, and the first interval after one reads `0`. The exception is a rule that comes back with the same body at the same handle, which nfrtop cannot tell from the same rule carrying on. The counters were reset with the ruleset, so what it reports for that one interval is the new counter minus the old one — `0` while the new counter is still below the old, and an undercount for the interval in which it passes it. Every interval after that is right again.

**Rules without a counter show `-`.** Only an anonymous `counter` statement gives a rule totals of its own, and a rule without one reports nothing rather than a zero it cannot vouch for. `--counted-only` drops those rules from the display altogether.

**`PKTS` and `BYTES` count what reached the counter, not what the rule matched.** nftables evaluates a rule left to right, so where the `counter` sits in it decides what it sees. `tcp dport 22 counter accept` counts what matched; `counter tcp dport 22 accept` counts everything that reached the rule, port 22 or not, and nfrtop reports the counter as nftables keeps it either way. A rule may also carry more than one: the first fills these columns, and any others are spelled out in `OPTIONS` in the position they occupy.

**A narrow terminal loses columns, not rules.** Columns shrink to their floors first, and after that the ones carrying the least — `OUT`, `IN`, `DEST`, `SOURCE`, `PROT`, and then the counters — are dropped, so that `OPTIONS` keeps saying what each rule does. What a dropped column had to say for a rule is handed back to `OPTIONS`, titled: a row that read `IN lo` under a column that is no longer there still reads `IN lo`. `NUM`, `TARGET`, `FAM` and `CHAIN` are the last to go and, from about 40 columns up, do not go at all; below that a row is cut at the right edge like any other line, because nothing else fits either. No line is ever wider than the terminal.

A live frame is also cut to the height of the terminal — scrolling would take the header and the first rules off the top — and the footer counts what did not fit, first, where a narrow footer still shows it. Redirected output is a document rather than a screen, and is never cut.

**What the ruleset says is data, not instructions.** Comments and names come from the ruleset, and this is normally run as root against a ruleset someone else may have written. Control characters in them are printed as `\x1b` and the like rather than sent to the terminal, so a comment cannot clear the screen, set the window title, or spread one rule across two lines. The same is done to whatever `nft` itself writes to stderr. Characters stdout cannot encode are escaped rather than raised — and escaped before the columns are sized, so a non-ASCII comment under `LC_ALL=C` is a wider cell rather than a traceback or a row that overruns the screen. Wide characters are counted as the two cells they take, so a CJK comment does not push the table sideways.

**Running under sudo.** When the effective user is root, nfrtop looks for `nft` in `/usr/sbin`, `/sbin`, `/usr/local/sbin`, `/usr/bin`, `/bin` and `/usr/local/bin` before consulting `PATH`, because under `sudo -E` — or an `env_keep`, or a relaxed `secure_path` — `PATH` can still be the invoking user's, and a writable directory on it would be a way to have something other than `nft` run as root. Prefer plain `sudo` over `sudo -E` regardless. Unprivileged runs use `PATH` as they always did.

## Development

```sh
python3 test_nfrtop.py                     # run the test suite
python3 test_nfrtop.py --update-golden     # re-record the golden output files
task check                                 # lint, then run the suite
```

Standard library only, and `nft` is not needed to run the tests: the fixtures under `tests/` are captured `nft -j list ruleset` dumps, so the parser is held to what a real nftables actually emits rather than to something hand-written.

There is a `Taskfile.yml` for the rest of it — `task` on its own lists what is there. `task test:matrix` runs the suite on every Python the CI covers, which is worth doing before cutting a tag. Linting is `ruff`, configured by `ruff.toml` and pinned to one version in both `Taskfile.yml` and CI, so a ruff release cannot turn a green tree red on its own.

## License

The MIT License
