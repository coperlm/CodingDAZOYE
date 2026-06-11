from __future__ import annotations

import argparse
import html
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List
import json
import shutil
import subprocess


@dataclass
class Vulnerability:
    filename: str
    line_number: int
    vulnerability_type: str
    code_snippet: str
    remediation: str
    severity: str = "MEDIUM"
    execution_path: List[str] = field(default_factory=list)


_BLACKLIST_RULES = {
    "strcpy": (
        "危险内存 API",
        "检测到危险函数 `strcpy`，建议替换为安全的带边界检查函数 "
        "`strncpy(dest, src, sizeof(dest) - 1);`",
        "HIGH",
    )
}

_STRCPY_CALL_PATTERN = re.compile(r"\bstrcpy\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)")


def strip_comments(source: str) -> str:
    result: List[str] = []
    in_single_line_comment = False
    in_multi_line_comment = False
    in_string = False
    in_char = False
    escaped = False
    i = 0

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if in_single_line_comment:
            if ch == "\n":
                in_single_line_comment = False
                result.append(ch)
            i += 1
            continue

        if in_multi_line_comment:
            if ch == "*" and nxt == "/":
                in_multi_line_comment = False
                i += 2
            else:
                if ch == "\n":
                    result.append("\n")
                i += 1
            continue

        if in_string:
            result.append(ch)
            if not escaped and ch == '"':
                in_string = False
            escaped = (ch == "\\") and not escaped
            i += 1
            continue

        if in_char:
            result.append(ch)
            if not escaped and ch == "'":
                in_char = False
            escaped = (ch == "\\") and not escaped
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_single_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_multi_line_comment = True
            i += 2
            continue

        if ch == '"':
            in_string = True
            escaped = False
            result.append(ch)
            i += 1
            continue

        if ch == "'":
            in_char = True
            escaped = False
            result.append(ch)
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def _detect_blacklist(lines: Iterable[str], filename: str) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    for line_no, line in enumerate(lines, start=1):
        for func_name, (vuln_type, default_remediation, severity) in _BLACKLIST_RULES.items():
            if re.search(rf"\b{re.escape(func_name)}\s*\(", line):
                remediation = default_remediation
                if func_name == "strcpy":
                    match = _STRCPY_CALL_PATTERN.search(line)
                    if match:
                        dest = match.group(1).strip()
                        src = match.group(2).strip()
                        remediation = (
                            "检测到危险函数 `strcpy`，建议替换为安全的带边界检查函数 "
                            f"`strncpy({dest}, {src}, sizeof({dest}) - 1);`"
                        )
                findings.append(
                    Vulnerability(
                        filename=filename,
                        line_number=line_no,
                        vulnerability_type=vuln_type,
                        code_snippet=line.strip(),
                        remediation=remediation,
                        severity=severity,
                    )
                )
    return findings


def _detect_concurrency_issues(lines: List[str], filename: str) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    # Tracks active critical sections as (line_number, code_snippet) tuples.
    lock_stack: List[tuple[int, str]] = []

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        if "EnterCriticalSection" in stripped:
            lock_stack.append((line_no, stripped))

        if lock_stack and re.search(r"\b(return|break)\b|exit\s*\(", stripped):
            lock_chain = [f"[Line {ln}] 锁被获取: {code}" for ln, code in lock_stack]
            findings.append(
                Vulnerability(
                    filename=filename,
                    line_number=line_no,
                    vulnerability_type="临界区未释放退出",
                    code_snippet=stripped,
                    remediation="检测到临界区未释放即退出，可能导致全局死锁。请确保先调用 LeaveCriticalSection。",
                    severity="CRITICAL",
                    execution_path=lock_chain
                    + [f"[Line {line_no}] 异常退出: {stripped} (致命: 锁未释放!)"],
                )
            )

        if "LeaveCriticalSection" in stripped and lock_stack:
            lock_stack.pop()
# 因为 TerminateThread 这个 API 本身在微软官方文档里就是极度危险的，会导致目标线程的资源直接被抛弃
        if "TerminateThread" in stripped:
            findings.append(
                Vulnerability(
                    filename=filename,
                    line_number=line_no,
                    vulnerability_type="架构级风险 API",
                    code_snippet=stripped,
                    remediation="检测到 `TerminateThread`，建议改用事件通知 (Event) 或协作式退出机制优雅停止线程。",
                    severity="HIGH",
                )
            )
    return findings


def analyze_source(source: str, filename: str) -> tuple[str, List[Vulnerability]]:
    clean_source = strip_comments(source)
    lines = clean_source.splitlines()
    findings = _detect_blacklist(lines, filename)
    findings.extend(_detect_concurrency_issues(lines, filename))
    findings.sort(key=lambda item: (item.line_number, item.vulnerability_type))
    return clean_source, findings


def analyze_file(path: Path) -> tuple[str, List[Vulnerability]]:
    raw = path.read_text(encoding="utf-8")
    return analyze_source(raw, filename=path.name)


def _detect_language(path: Path, source_text: str = "") -> str:
    suffix = path.suffix.lower()
    if suffix in (".c", ".h"):
        return "c"
    if suffix in (".cpp", ".cc", ".cxx", ".hpp", ".hh"):
        return "cpp"
    if suffix in (".java",):
        return "java"
    if suffix in (".py",):
        return "python"
    if source_text:
        if re.search(r"\bdef\s+\w+\s*\(|\bimport\s+\w+", source_text) and "#include" not in source_text:
            return "python"
        if re.search(r"#include\s*[<\"]|\busing\s+namespace\s+std\b|\bstd::|\bcout\b|\bCRITICAL_SECTION\b|\bHANDLE\b", source_text):
            return "cpp"
    return "unknown"


def _parse_semgrep_json(json_text: str, source_path: Path, filename: str) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    try:
        payload = json.loads(json_text)
    except Exception:
        return findings

    results = payload.get("results", []) if isinstance(payload, dict) else []
    for res in results:
        try:
            path = res.get("path") or res.get("extra", {}).get("metadata", {}).get("path") or filename
            start = res.get("start", {})
            line_no = start.get("line", 0) if isinstance(start, dict) else 0
            message = res.get("extra", {}).get("message", "")
            check_id = res.get("check_id", "semgrep")
            remediation = res.get("extra", {}).get("metadata", {}).get("remediation", "") or "请参考 Semgrep 规则建议。"
            code_snippet = _semgrep_code_snippet(source_path, line_no, res.get("extra", {}).get("lines"))
            findings.append(
                Vulnerability(
                    filename=Path(path).name,
                    line_number=line_no,
                    vulnerability_type=_normalize_semgrep_rule_id(check_id),
                    code_snippet=code_snippet,
                    remediation=remediation,
                    severity=_normalize_semgrep_severity(res.get("extra", {}).get("severity", "MEDIUM")),
                )
            )
        except Exception:
            continue
    return findings


def _semgrep_code_snippet(source_path: Path, line_no: int, fallback: str) -> str:
    try:
        lines = source_path.read_text(encoding="utf-8").splitlines()
        if 1 <= line_no <= len(lines):
            snippet = lines[line_no - 1].strip()
            if snippet:
                return snippet
    except Exception:
        pass
    return fallback or ""


def _normalize_semgrep_rule_id(rule_id: str) -> str:
    normalized = rule_id or "semgrep"
    if normalized.startswith("semgrep-rules."):
        return normalized.removeprefix("semgrep-rules.")
    return normalized


def _normalize_semgrep_severity(severity: str) -> str:
    normalized = (severity or "MEDIUM").upper()
    if normalized == "ERROR":
        return "HIGH"
    if normalized == "WARNING":
        return "MEDIUM"
    if normalized == "INFO":
        return "LOW"
    if normalized not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return "MEDIUM"
    return normalized


def _run_semgrep_on_file(path: Path) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return findings

    # Prefer using the checked-in semgrep-rules submodule when available.
    rules_dir = Path("semgrep-rules")
    try:
        source_text = path.read_text(encoding="utf-8")
    except Exception:
        source_text = ""

    language = _detect_language(path, source_text)
    config_paths: List[str] = []
    if rules_dir.exists():
        if language in ("c", "cpp"):
            config_paths = [str(rules_dir / "c"), str(rules_dir / "generic")]
        elif language == "java":
            config_paths = [str(rules_dir / "java"), str(rules_dir / "generic")]
        elif language == "python":
            config_paths = [str(rules_dir / "python"), str(rules_dir / "generic")]
        else:
            config_paths = [str(rules_dir / "generic")]

    if not config_paths:
        config_paths = ["auto"]

    try:
        command = [semgrep_bin, "--json"]
        for config_path in config_paths:
            command.extend(["--config", config_path])
        command.append(str(path))
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        if proc.returncode == 0 or proc.stdout:
            findings = _parse_semgrep_json(proc.stdout, source_path=path, filename=path.name)
    except Exception:
        pass

    return findings


def _render_console(path: Path, findings: List[Vulnerability]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover
        Console = None

    if Console is None:
        print("\n=== 漏洞检测结果 ===")
        if not findings:
            print("未发现漏洞。")
        for item in findings:
            print(f"[{item.severity}] {item.filename}:{item.line_number} {item.vulnerability_type}")
            print(f"代码: {item.code_snippet}")
            print(f"修复建议: {item.remediation}")
            if item.execution_path:
                print("执行路径:")
                for p in item.execution_path:
                    print(f"  {p}")
        return

    console = Console()
    console.rule("[bold red]漏洞检测结果")
    if not findings:
        console.print("[green]未发现漏洞。[/green]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("等级")
    table.add_column("位置")
    table.add_column("类型")
    table.add_column("代码")
    table.add_column("修复建议")
    for item in findings:
        sev = {"CRITICAL": "[red]CRITICAL[/red]", "HIGH": "[red]HIGH[/red]"}.get(
            item.severity, "[yellow]MEDIUM[/yellow]"
        )
        table.add_row(
            sev,
            f"{item.filename}:{item.line_number}",
            item.vulnerability_type,
            item.code_snippet,
            f"[green]{item.remediation}[/green]",
        )
    console.print(table)

    critical_items = [item for item in findings if item.execution_path]
    for item in critical_items:
        console.print("\n[bold red]污染链 / Execution Path[/bold red]")
        for step in item.execution_path:
            console.print(f"[red]{step}[/red]")


def _render_html(findings: List[Vulnerability], output_path: Path) -> None:
    rows = []
    for item in findings:
        execution = "<br/>".join(html.escape(step) for step in item.execution_path) or "-"
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.severity)}</td>"
            f"<td>{html.escape(item.filename)}:{item.line_number}</td>"
            f"<td>{html.escape(item.vulnerability_type)}</td>"
            f"<td><pre>{html.escape(item.code_snippet)}</pre></td>"
            f"<td>{html.escape(item.remediation)}</td>"
            f"<td>{execution}</td>"
            "</tr>"
        )

    html_body = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>ThreadViper 漏洞报告</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #222; color: #fff; }}
    .CRITICAL, .HIGH {{ color: #b30000; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>ThreadViper 漏洞报告</h1>
  <table>
    <thead>
      <tr>
        <th>等级</th><th>位置</th><th>类型</th><th>代码</th><th>修复建议</th><th>执行路径</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>"""
    output_path.write_text(html_body, encoding="utf-8")


def _default_html_path(paths: List[Path]) -> Path:
    if len(paths) == 1:
        return paths[0].with_suffix(".html")
    return Path("threadviper-report.html")


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreadViper: 多语言（C/C++/Java）并发与安全检测工具")
    parser.add_argument("source", nargs="+", help="待检测的源文件路径（支持 C/C++/Java）")
    parser.add_argument("--html", dest="html_path", help="输出 HTML 报告路径（可选，默认自动生成）")
    args = parser.parse_args()

    source_paths = [Path(source) for source in args.source]
    html_path = Path(args.html_path) if args.html_path else _default_html_path(source_paths)

    all_findings: List[Vulnerability] = []
    for path in source_paths:
        try:
            raw_source = path.read_text(encoding="utf-8")
        except Exception:
            raw_source = ""

        language = _detect_language(path, raw_source)

        findings: List[Vulnerability] = []

        # Native simple analyzer (original implementation) for C/C++ files
        if language in ("c", "cpp"):
            clean_source, local_findings = analyze_source(raw_source, filename=path.name)
            findings.extend(local_findings)
        else:
            # For unknown languages still try to read source for console rendering
            clean_source = raw_source

        # Try Semgrep-based analysis when available (covers many languages incl. Java/C)
        semgrep_findings = _run_semgrep_on_file(path)
        if semgrep_findings:
            findings.extend(semgrep_findings)

        # Deduplicate by (filename, line, type)
        seen = set()
        unique_findings: List[Vulnerability] = []
        for f in findings:
            key = (f.filename, f.line_number, f.vulnerability_type)
            if key in seen:
                continue
            seen.add(key)
            unique_findings.append(f)

        _render_console(path, unique_findings)
        all_findings.extend(unique_findings)

    _render_html(all_findings, html_path)
    print(f"\nHTML 报告已生成: {html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
