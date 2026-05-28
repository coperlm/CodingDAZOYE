from __future__ import annotations

import argparse
import html
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List


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
        "`strncpy(newPcb->name, name, sizeof(newPcb->name) - 1);`",
        "HIGH",
    )
}


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
        for func_name, (vuln_type, remediation, severity) in _BLACKLIST_RULES.items():
            if re.search(rf"\b{re.escape(func_name)}\s*\(", line):
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


def _render_console(path: Path, clean_source: str, findings: List[Vulnerability]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:  # pragma: no cover
        Console = None

    if Console is None:
        print(f"\n=== {path.name} 去注释结果 ===")
        print(clean_source)
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
    console.rule(f"[bold cyan]{path.name} 去注释结果")
    console.print(clean_source)
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


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreadViper: C/C++ 并发与内存安全检测工具")
    parser.add_argument("source", nargs="+", help="待检测的 C/C++ 源文件路径")
    parser.add_argument("--html", dest="html_path", help="输出 HTML 报告路径（可选）")
    args = parser.parse_args()

    all_findings: List[Vulnerability] = []
    for source in args.source:
        path = Path(source)
        clean_source, findings = analyze_file(path)
        _render_console(path, clean_source, findings)
        all_findings.extend(findings)

    if args.html_path:
        _render_html(all_findings, Path(args.html_path))
        print(f"\nHTML 报告已生成: {args.html_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
