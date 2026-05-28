#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Callable, Iterable, List, Pattern

SUPPORTED_SUFFIXES = {".c", ".cpp", ".h", ".hpp", ".txt"}


@dataclass
class Vulnerability:
    file: str
    line: int
    kind: str
    code: str
    suggestion: str
    severity: str
    path: List[str] = field(default_factory=list)


@dataclass
class Rule:
    name: str
    pattern: Pattern[str]
    suggestion: Callable[[re.Match[str]], str]
    kind: str
    severity: str


STRCPY_PATTERN = re.compile(
    r"\bstrcpy\s*\(\s*(?P<dest>[^,]+?)\s*,\s*(?P<src>[^)]+?)\s*\)",
)
TERMINATE_THREAD_PATTERN = re.compile(r"\bTerminateThread\b")
ENTER_CS_PATTERN = re.compile(r"\bEnterCriticalSection\b")
LEAVE_CS_PATTERN = re.compile(r"\bLeaveCriticalSection\b")
CRITICAL_EXIT_PATTERN = re.compile(r"\breturn\b|\bbreak\b|\bexit\s*\(\s*0\s*\)")


def build_rules() -> List[Rule]:
    return [
        Rule(
            name="strcpy",
            pattern=STRCPY_PATTERN,
            suggestion=lambda match: _format_strncpy_suggestion(match),
            kind="Unsafe function: strcpy",
            severity="High",
        )
    ]


def _format_strncpy_suggestion(match: re.Match[str]) -> str:
    dest = match.group("dest").strip()
    src = match.group("src").strip()
    return f"strncpy({dest}, {src}, sizeof({dest}) - 1);"


def strip_comments(source: str) -> str:
    result: List[str] = []
    i = 0
    in_block_comment = False
    in_line_comment = False
    string_delim: str | None = None
    escape_next = False

    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""

        if in_line_comment:
            if char == "\n":
                in_line_comment = False
                result.append(char)
            i += 1
            continue

        if in_block_comment:
            if char == "*" and next_char == "/":
                in_block_comment = False
                i += 2
                continue
            if char == "\n":
                result.append(char)
            i += 1
            continue

        if string_delim:
            result.append(char)
            if escape_next:
                escape_next = False
            elif char == "\\":
                escape_next = True
            elif char == string_delim:
                string_delim = None
            i += 1
            continue

        if char in ('"', "'"):
            string_delim = char
            result.append(char)
            i += 1
            continue

        if char == "/" and next_char == "/":
            in_line_comment = True
            i += 2
            continue

        if char == "/" and next_char == "*":
            in_block_comment = True
            i += 2
            continue

        result.append(char)
        i += 1

    return "".join(result)


def collect_targets(paths: Iterable[str]) -> List[Path]:
    targets: List[Path] = []
    seen = set()
    if not paths:
        paths = [str(Path.cwd())]

    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file() and candidate.suffix.lower() in SUPPORTED_SUFFIXES:
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        targets.append(resolved)
        elif path.is_file():
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                targets.append(resolved)

    return sorted(targets)


def scan_file(file_path: Path, rules: List[Rule]) -> List[Vulnerability]:
    raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
    sanitized = strip_comments(raw_text)
    vulnerabilities: List[Vulnerability] = []

    critical_depth = 0
    critical_path: List[str] = []

    for line_number, line in enumerate(sanitized.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        entered = bool(ENTER_CS_PATTERN.search(line))
        left = bool(LEAVE_CS_PATTERN.search(line))

        if critical_depth > 0 or entered:
            critical_path.append(f"[Line {line_number}] {stripped}")

        if entered:
            critical_depth += 1

        if critical_depth > 0 and CRITICAL_EXIT_PATTERN.search(line):
            vulnerabilities.append(
                Vulnerability(
                    file=str(file_path),
                    line=line_number,
                    kind="Critical section exit without release",
                    code=stripped,
                    suggestion="Ensure LeaveCriticalSection is called before exiting the critical section.",
                    severity="Critical",
                    path=list(critical_path),
                )
            )

        for rule in rules:
            for match in rule.pattern.finditer(line):
                vulnerabilities.append(
                    Vulnerability(
                        file=str(file_path),
                        line=line_number,
                        kind=rule.kind,
                        code=stripped,
                        suggestion=rule.suggestion(match),
                        severity=rule.severity,
                    )
                )

        if TERMINATE_THREAD_PATTERN.search(line):
            vulnerabilities.append(
                Vulnerability(
                    file=str(file_path),
                    line=line_number,
                    kind="Dangerous API: TerminateThread",
                    code=stripped,
                    suggestion=(
                        "Avoid TerminateThread; signal the thread with an Event or flag and let it exit gracefully."
                    ),
                    severity="High",
                )
            )

        if left and critical_depth > 0:
            critical_depth -= 1
            if critical_depth == 0:
                critical_path.clear()

    return vulnerabilities


def colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    palette = {
        "red": "\033[31m",
        "yellow": "\033[33m",
        "green": "\033[32m",
        "cyan": "\033[36m",
        "reset": "\033[0m",
    }
    return f"{palette.get(color, '')}{text}{palette['reset']}"


def severity_color(severity: str) -> str:
    mapping = {
        "Critical": "red",
        "High": "yellow",
        "Medium": "yellow",
        "Low": "cyan",
    }
    return mapping.get(severity, "cyan")


def print_report(vulnerabilities: List[Vulnerability], use_color: bool) -> None:
    if not vulnerabilities:
        print(colorize("No vulnerabilities found.", "green", use_color))
        return

    for vuln in vulnerabilities:
        header = f"{vuln.severity}: {vuln.kind}"
        print(colorize(header, severity_color(vuln.severity), use_color))
        print(f"  File: {vuln.file}")
        print(f"  Line: {vuln.line}")
        print(f"  Code: {vuln.code}")
        print(colorize(f"  Fix:  {vuln.suggestion}", "green", use_color))
        if vuln.path:
            print(colorize("  Execution Path:", "cyan", use_color))
            for entry in vuln.path:
                print(colorize(f"    {entry}", "cyan", use_color))
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreadViper - C/C++ safety scanner")
    parser.add_argument("paths", nargs="*", help="Files or directories to scan")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    targets = collect_targets(args.paths)
    if not targets:
        print("No matching files found to scan.")
        return 1

    rules = build_rules()
    findings: List[Vulnerability] = []
    for target in targets:
        findings.extend(scan_file(target, rules))

    print_report(findings, use_color=not args.no_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
