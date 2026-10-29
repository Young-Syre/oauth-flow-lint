"""Command line interface.

Exit codes are part of the contract, so they are documented here, in the
``--help`` epilogue, and in the README:

* ``0`` - the configuration produced no finding at or above the failure
  threshold. For ``plan``, ``rules`` and ``init``, success.
* ``1`` - at least one finding at or above the threshold.
* ``2`` - the tool could not do its job: a configuration that will not parse, a
  value outside its permitted set, a file that cannot be read, a bad argument.

The distinction between 1 and 2 is the one that matters in a pipeline: 1 is an
answer, 2 is the absence of one.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TextIO

from . import __version__, engine, probes, report
from .findings import RULES, Severity
from .loader import ConfigError, load_file
from .scaffold import scaffold_text

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

EPILOGUE = """\
exit codes:
  0  no findings at or above the failure threshold (default: medium)
  1  at least one finding at or above the failure threshold
  2  the configuration could not be read or understood, or the arguments were invalid

This tool performs no network requests. A provider metadata document must be
saved to a local JSON file and referenced by path; the plan subcommand prints
requests for a human to send, and sends nothing itself.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oauth-flow-lint",
        description=(
            "Lint an OAuth 2.0 / OpenID Connect client configuration offline, and report the "
            "combinations of weaknesses that escalate into each other."
        ),
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"oauth-flow-lint {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add_format(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--format",
            choices=("text", "json", "markdown"),
            default="text",
            help="output format (default: text)",
        )

    lint = sub.add_parser(
        "lint",
        help="check a configuration and report findings and escalations",
        description="Check a configuration and report findings and escalations.",
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    lint.add_argument("config", help="path to a TOML configuration file")
    add_format(lint)
    lint.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        default="medium",
        help="lowest severity that makes the exit code 1 (default: medium)",
    )
    lint.add_argument(
        "--all",
        action="store_true",
        dest="show_all",
        help="show findings below the failure threshold as well",
    )

    plan = sub.add_parser(
        "plan",
        help="print the probe list that confirms the provider's real behaviour",
        description=(
            "Print the exact requests a tester should send to establish how the provider really "
            "compares redirect URIs and which parameters it really requires. Sends nothing."
        ),
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    plan.add_argument("config", help="path to a TOML configuration file")
    add_format(plan)

    init = sub.add_parser(
        "init",
        help="write a commented scaffold configuration",
        description="Write a commented scaffold configuration. The scaffold lints clean.",
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    init.add_argument(
        "path",
        nargs="?",
        help="file to write (default: standard output)",
    )
    init.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing file",
    )

    rules = sub.add_parser(
        "rules",
        help="print the rule catalogue and the escalation matrix",
        description="Print the rule catalogue and the escalation matrix.",
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_format(rules)
    rules.add_argument(
        "--matrix",
        action="store_true",
        help="print only the escalation matrix",
    )

    return parser


def _cmd_lint(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = load_file(args.config)
    result = engine.run(config)
    threshold = Severity.parse(args.fail_on)
    if args.format == "json":
        out.write(report.render_json(result, threshold, args.show_all))
    elif args.format == "markdown":
        out.write(report.render_markdown(result, threshold, args.show_all))
    else:
        out.write(report.render_text(result, threshold, args.show_all))
    if config.unknown_keys and args.format != "text":
        for key in config.unknown_keys:
            err.write(f"warning: unrecognised configuration key: {key}\n")
    return EXIT_FINDINGS if result.at_or_above(threshold) else EXIT_OK


def _cmd_plan(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    config = load_file(args.config)
    built = probes.build(config)
    if args.format == "json":
        out.write(report.render_plan_json(built, config.source_path))
    elif args.format == "markdown":
        out.write(report.render_plan_markdown(built, config.source_path))
    else:
        out.write(report.render_plan_text(built, config.source_path))
    return EXIT_OK


def _cmd_init(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    text = scaffold_text()
    if not args.path:
        out.write(text)
        return EXIT_OK
    path = Path(args.path)
    if path.exists() and not args.force:
        err.write(f"error: {path} already exists; pass --force to overwrite\n")
        return EXIT_ERROR
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        err.write(f"error: cannot write {path}: {exc.strerror}\n")
        return EXIT_ERROR
    err.write(f"wrote {path}\n")
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace, out: TextIO, err: TextIO) -> int:
    if args.format == "json":
        out.write(report.render_rules_json(args.matrix))
    elif args.format == "markdown":
        out.write(report.render_rules_markdown(args.matrix))
    else:
        out.write(report.render_rules_text(args.matrix))
    return EXIT_OK


HANDLERS = {
    "lint": _cmd_lint,
    "plan": _cmd_plan,
    "init": _cmd_init,
    "rules": _cmd_rules,
}


def main(
    argv: list[str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr

    if not args.command:
        parser.print_help(out)
        return EXIT_ERROR

    try:
        return HANDLERS[args.command](args, out, err)
    except ConfigError as exc:
        err.write(f"error: {exc}\n")
        return EXIT_ERROR


# Sanity check at import time: every rule the catalogue holds must have a
# severity the CLI can express, and the --fail-on choices must cover them.
assert all(r.severity in set(Severity) for r in RULES.values())
