import unittest
import json

from threadviper import analyze_source, strip_comments, _detect_language, _parse_semgrep_json, _default_html_path, _build_semgrep_remediation


class ThreadViperTests(unittest.TestCase):
    def test_strip_comments_removes_single_and_multi_line(self) -> None:
        code = 'int a = 1; // comment\nchar* s = "http://x"; /* block */\nint b = 2;'
        clean = strip_comments(code)
        self.assertNotIn("// comment", clean)
        self.assertNotIn("block", clean)
        self.assertIn('"http://x"', clean)

    def test_strip_comments_removes_python_comments(self) -> None:
        code = 'import os  # keep import\ntext = "a # not comment"\nvalue = 1  # trailing\n'
        clean = strip_comments(code, language="python")
        self.assertNotIn("# keep import", clean)
        self.assertNotIn("# trailing", clean)
        self.assertIn('"a # not comment"', clean)

    def test_analyze_source_runs_semgrep_for_c(self) -> None:
        code = "void f(char *dst, char *src){ strcpy(dst, src); }"
        _, findings = analyze_source(code, "sample.c", language="c")
        self.assertTrue(findings)
        self.assertTrue(any("strcpy" in f.code_snippet for f in findings))

    def test_analyze_source_runs_semgrep_for_python(self) -> None:
        code = (
            "import subprocess\n"
            "\n"
            "def route_param(route_param):\n"
            "    subprocess.call(\"grep -R {} .\".format(route_param), shell=True, cwd=\"/tmp\")\n"
        )
        _, findings = analyze_source(code, "demo.py", language="python")
        self.assertTrue(findings)
        self.assertTrue(any("grep" in f.code_snippet for f in findings))

    def test_detect_language_supports_c_cpp_and_java(self) -> None:
        from pathlib import Path

        self.assertEqual(_detect_language(Path("demo.c")), "c")
        self.assertEqual(_detect_language(Path("demo.cpp")), "cpp")
        self.assertEqual(_detect_language(Path("Demo.java")), "java")
        self.assertEqual(_detect_language(Path("demo.py")), "python")
        self.assertEqual(_detect_language(Path("测试用例1.txt"), "#include <windows.h>\nusing namespace std;"), "cpp")
        self.assertEqual(_detect_language(Path("demo.txt"), "def run():\n    import subprocess"), "python")

    def test_parse_semgrep_json_handles_result_payload(self) -> None:
        payload = {
            "results": [
                {
                    "path": "src/Demo.java",
                    "start": {"line": 12},
                    "check_id": "java.lang.security.demo",
                    "extra": {
                        "message": "Dangerous API usage",
                        "severity": "HIGH",
                        "lines": "Runtime.getRuntime().exec(\"bash\", \"-c\", input);",
                        "metadata": {"remediation": "Use a safe alternative."},
                    },
                }
            ]
        }
        from pathlib import Path

        findings = _parse_semgrep_json(json.dumps(payload), source_text='Runtime.getRuntime().exec("bash", "-c", input);', filename="Demo.java")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].filename, "Demo.java")
        self.assertEqual(findings[0].line_number, 12)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].vulnerability_type, "java.lang.security.demo")
        self.assertIn("Runtime.getRuntime().exec", findings[0].code_snippet)
        self.assertIn("ProcessBuilder", findings[0].remediation)

    def test_build_semgrep_remediation_is_rule_specific(self) -> None:
        self.assertIn(
            "subprocess.run",
            _build_semgrep_remediation(
                "python.lang.security.dangerous-subprocess-use",
                "Detected subprocess function",
                'subprocess.call("grep", shell=True)',
            ),
        )
        self.assertIn(
            "yaml.safe_load",
            _build_semgrep_remediation(
                "python.lang.security.deserialization.avoid-pyyaml-load",
                "yaml.load on untrusted input",
                'yaml.load(data)',
            ),
        )
        self.assertIn(
            "check=True",
            _build_semgrep_remediation(
                "python.lang.correctness.unchecked-subprocess-call",
                "This is not checking the return value of this subprocess call",
                'subprocess.call("grep", shell=True)',
            ),
        )
        self.assertIn(
            "strncpy_s",
            _build_semgrep_remediation(
                "c.lang.security.strcpy",
                "buffer overflow",
                'strcpy(dst, src);',
            ),
        )

    def test_default_html_path_is_inferred_from_input(self) -> None:
        from pathlib import Path

        self.assertEqual(_default_html_path([Path("samples/c_demo.c")]).name, "c_demo.html")
        self.assertEqual(_default_html_path([Path("a.c"), Path("b.java")]).name, "threadviper-report.html")


if __name__ == "__main__":
    unittest.main()
