"""Command line interface: the `agent-threat-model` console script.

Commands:

- ``agent-threat-model analyze <spec.json> [--format markdown|json|text] [--fail-on LEVEL]``
- ``agent-threat-model catalog``
- ``agent-threat-model example [--write PATH]``
- ``agent-threat-model validate <spec.json>``

Exit codes:

- 0: success. For analyze, no threat at or above the fail-on level.
- 1: analyze found a threat at or above the fail-on level (default high).
- 2: usage or input error: an unreadable or invalid spec.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_threat_model import __version__
from agent_threat_model.engine import RULES, SEVERITY_RANK
from agent_threat_model.example import EXAMPLE_SPEC
from agent_threat_model.models import Architecture, SpecError
from agent_threat_model.report import build_threat_model

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _load(path_str: str) -> Architecture:
    return Architecture.from_json_file(path_str)


def cmd_analyze(args: argparse.Namespace) -> int:
    try:
        arch = _load(args.spec)
    except SpecError as exc:
        print(f"error: cannot load spec: {exc}", file=sys.stderr)
        return EXIT_USAGE
    model = build_threat_model(arch)
    if args.format == "json":
        print(model.to_json(), end="")
    elif args.format == "text":
        print(model.to_text(), end="")
    else:
        print(model.to_markdown())
    threshold = SEVERITY_RANK[args.fail_on]
    if any(SEVERITY_RANK[t.severity] <= threshold for t in model.threats):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_catalog(args: argparse.Namespace) -> int:
    print("| ID | Severity | STRIDE | Rule |")
    print("|---|---|---|---|")
    for rule in RULES:
        print(f"| {rule.id} | {rule.severity} | {rule.stride} | {rule.title} |")
    print(f"\n{len(RULES)} rules in the catalog.")
    return EXIT_OK


def cmd_example(args: argparse.Namespace) -> int:
    text = json.dumps(EXAMPLE_SPEC, indent=2) + "\n"
    if args.write:
        try:
            Path(args.write).write_text(text, encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write example: {exc}", file=sys.stderr)
            return EXIT_USAGE
        print(f"wrote example spec to {args.write}")
    else:
        print(text, end="")
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        arch = _load(args.spec)
    except SpecError as exc:
        print(f"error: invalid spec: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(
        f"OK: {arch.name} parses "
        f"({len(arch.inputs)} inputs, {len(arch.tools)} tools, "
        f"{len(arch.data)} data items, {len(arch.mcp_servers)} MCP servers)"
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-threat-model",
        description="Threat modeling for AI agent apps.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="analyze a spec and print the threat model")
    p_analyze.add_argument("spec", help="architecture spec JSON file")
    p_analyze.add_argument("--format", choices=["markdown", "json", "text"], default="markdown")
    p_analyze.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="exit 1 when any threat is at or above this severity (default high)",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    p_catalog = sub.add_parser("catalog", help="print the rule catalog")
    p_catalog.set_defaults(func=cmd_catalog)

    p_example = sub.add_parser("example", help="print or write the bundled example spec")
    p_example.add_argument("--write", default=None, help="write the example spec to this path")
    p_example.set_defaults(func=cmd_example)

    p_validate = sub.add_parser("validate", help="check that a spec parses")
    p_validate.add_argument("spec", help="architecture spec JSON file")
    p_validate.set_defaults(func=cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
