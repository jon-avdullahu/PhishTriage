"""Command line: python -m phishtriage analyze <file.eml | folder> ...

Exit codes: 0 every file was triaged, 1 at least one file could not be read, 2 usage or config error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import DEFAULT_CONFIG, ConfigError, load_config
from .mail import MailError
from .triage import ACTIONS, triage_file


def _expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.iterdir() if p.suffix.lower() == ".eml"))
        else:
            files.append(path)
    return files


def _format_text(result: dict) -> str:
    if "error" in result:
        return f"[ERROR] {result['file']}: {result['error']}"
    lines = [
        f"[{result['verdict'].upper()} {result['score']}] {result['file']}",
        f"  Subject: {result['subject']}",
        f"  From:    {result['sender']}",
    ]
    lines += [f"  - {f['code']} (+{f['weight']}): {f['message']}" for f in result["findings"]]
    if result["iocs"]["domains"]:
        lines.append(f"  Domains: {', '.join(result['iocs']['domains'])}")
    if result["iocs"]["ips"]:
        lines.append(f"  IPs:     {', '.join(result['iocs']['ips'])}")
    lines += [f"  > {action}" for action in ACTIONS[result["verdict"]]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishtriage", description="Triage reported phishing e-mails offline.")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="triage .eml files or folders of .eml files")
    analyze.add_argument("paths", nargs="+")
    analyze.add_argument("--config", help="JSON config file (default: built-in Contoso example)")
    analyze.add_argument("--format", choices=("text", "json"), default="text")
    analyze.add_argument("--output", help="write to this file (UTF-8) instead of the console")
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config) if args.config else DEFAULT_CONFIG
    except ConfigError as exc:
        print(f"phishtriage: {exc}", file=sys.stderr)
        return 2

    files = _expand(args.paths)
    if not files:
        print("phishtriage: no .eml files found", file=sys.stderr)
        return 2

    results: list[dict] = []
    failed = False
    for file in files:
        try:
            results.append(triage_file(file, config).to_dict())
        except (OSError, MailError) as exc:
            failed = True
            results.append({"file": file.name, "error": str(exc)})

    if args.format == "json":
        output = json.dumps(results, indent=2, ensure_ascii=False)
    else:
        output = "\n\n".join(_format_text(r) for r in results)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        print(output)
    return 1 if failed else 0
