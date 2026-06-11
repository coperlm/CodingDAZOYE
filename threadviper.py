from __future__ import annotations

import argparse
import html
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List
import json
import shutil
import subprocess
import tempfile
import tokenize


@dataclass
class Vulnerability:
    filename: str
    line_number: int
    vulnerability_type: str
    code_snippet: str
    remediation: str
    severity: str = "MEDIUM"
    execution_path: List[str] = field(default_factory=list)

def _strip_python_comments(source: str) -> str:
    tokens: List[tuple[int, str]] = []
    reader = io.StringIO(source).readline
    try:
        for token in tokenize.generate_tokens(reader):
            if token.type in (tokenize.COMMENT, tokenize.ENCODING):
                continue
            tokens.append((token.type, token.string))
    except tokenize.TokenError:
        return source

    return tokenize.untokenize(tokens)


def strip_comments(source: str, language: str = "cpp") -> str:
    if language == "python":
        return _strip_python_comments(source)

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


def analyze_source(source: str, filename: str, language: str | None = None) -> tuple[str, List[Vulnerability]]:
    if language is None:
        language = _detect_language(Path(filename), source)

    clean_source = strip_comments(source, language)
    findings = _run_semgrep_on_source(filename=filename, source_text=clean_source, language=language)
    findings.sort(key=lambda item: (item.line_number, item.vulnerability_type))
    return clean_source, findings


def analyze_file(path: Path) -> tuple[str, List[Vulnerability]]:
    raw = path.read_text(encoding="utf-8")
    language = _detect_language(path, raw)
    return analyze_source(raw, filename=path.name, language=language)


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


def _parse_semgrep_json(json_text: str, source_text: str, filename: str) -> List[Vulnerability]:
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
            code_snippet = _semgrep_code_snippet(source_text, line_no, res.get("extra", {}).get("lines"))
            remediation = _build_semgrep_remediation(
                rule_id=_normalize_semgrep_rule_id(check_id),
                message=message,
                code_snippet=code_snippet,
            )
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


def _semgrep_code_snippet(source_text: str, line_no: int, fallback: str) -> str:
    lines = source_text.splitlines()
    if 1 <= line_no <= len(lines):
        snippet = lines[line_no - 1].strip()
        if snippet:
            return snippet
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


def _build_semgrep_remediation(rule_id: str, message: str, code_snippet: str) -> str:
    haystack = f"{rule_id}\n{message}\n{code_snippet}".lower()

    if (
        "dangerous-subprocess-use" in haystack
        or "command-injection" in haystack
        or "injection" in haystack and "subprocess" in haystack
        or "subprocess.call" in haystack
        or "subprocess.popen" in haystack
        or "shell=true" in haystack
    ):
        return (
            "不要把用户输入拼接到 shell=True 的命令中；改用 subprocess.run([...], shell=False, check=True) "
            "或 subprocess.call([...], shell=False)，把参数拆成独立列表，并对外部输入做白名单校验。"
        )

    if "return value of this subprocess call" in haystack or "unchecked" in haystack and "subprocess" in haystack:
        return (
            "如果你需要判断命令是否成功执行，改用 subprocess.run(..., check=True) 或 subprocess.check_call(...); "
            "如果继续使用 call/run，请显式检查 returncode 并处理失败分支。"
        )

    if "command-injection" in haystack or "runtime.getruntime().exec" in haystack or "loadlibrary" in haystack:
        return (
            "不要把动态字符串直接传给 Runtime.exec / loadLibrary；改用固定参数数组或 ProcessBuilder，"
            "避免 bash -c / sh -c，把外部输入先做白名单校验或转义后再使用。"
        )

    if "yaml.load" in haystack or "deserialization" in haystack or "unsafe loader" in haystack:
        return (
            "不要使用 yaml.load 解析不可信输入；改为 yaml.safe_load 或显式指定 SafeLoader，"
            "只允许受信任的数据结构和标签。"
        )

    if "strcpy" in haystack or "strncpy" in haystack or "buffer overflow" in haystack:
        return (
            "不要使用 strcpy；改为 strncpy_s、snprintf 或带长度检查的拷贝方式，"
            "并在拷贝后手动补 '\\0'，确保目标缓冲区长度足够。"
        )

    if "xss" in haystack or "html" in haystack or "template" in haystack:
        return (
            "对输出内容做 HTML 转义，启用模板引擎的自动转义，把用户输入和页面渲染分离。"
        )

    if "sql" in haystack or "sqli" in haystack:
        return (
            "改用参数化查询或预编译语句，不要拼接 SQL 字符串。"
        )

    if "deserialize" in haystack:
        return (
            "不要反序列化不可信输入；改为受限反序列化、签名校验或安全数据格式。"
        )

    if message:
        return (
            f"建议按该规则上下文替换为更安全的 API 和输入校验方式；Semgrep 提示：{message}"
        )

    return "建议按该规则上下文替换为更安全的 API 和输入校验方式。"


def _run_semgrep_on_source(filename: str, source_text: str, language: str) -> List[Vulnerability]:
    findings: List[Vulnerability] = []
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        return findings

    # Prefer using the checked-in semgrep-rules submodule when available.
    rules_dir = Path("semgrep-rules")
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

    suffix_map = {"c": ".c", "cpp": ".c", "java": ".java", "python": ".py"}
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix_map.get(language, ".txt"), delete=False) as temp_file:
            temp_file.write(source_text)
            temp_path = Path(temp_file.name)

        command = [semgrep_bin, "--json"]
        for config_path in config_paths:
            command.extend(["--config", config_path])
        command.append(str(temp_path))
        proc = subprocess.run(command, capture_output=True, text=True, check=False)
        if proc.returncode == 0 or proc.stdout:
            findings = _parse_semgrep_json(proc.stdout, source_text=source_text, filename=filename)
    except Exception:
        pass
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
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

        _clean_source, findings = analyze_source(raw_source, filename=path.name, language=language)

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
