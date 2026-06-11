import unittest
import json

from threadviper import analyze_source, strip_comments, _detect_language, _parse_semgrep_json, _default_html_path


class ThreadViperTests(unittest.TestCase):
    def test_strip_comments_removes_single_and_multi_line(self) -> None:
        code = 'int a = 1; // comment\nchar* s = "http://x"; /* block */\nint b = 2;'
        clean = strip_comments(code)
        self.assertNotIn("// comment", clean)
        self.assertNotIn("block", clean)
        self.assertIn('"http://x"', clean)

    def test_detects_strcpy(self) -> None:
        code = "void f(){ strcpy(p->name, \"NoName\"); }"
        _, findings = analyze_source(code, "schedule.cpp")
        self.assertTrue(any(f.vulnerability_type == "危险内存 API" for f in findings))
        remediation = next(f.remediation for f in findings if f.vulnerability_type == "危险内存 API")
        self.assertIn("strncpy(p->name, \"NoName\", sizeof(p->name) - 1);", remediation)

    def test_detects_critical_section_early_exit(self) -> None:
        code = """
        void f() {
            EnterCriticalSection(&cs_SaveInfo);
            if (x) return;
            LeaveCriticalSection(&cs_SaveInfo);
        }
        """
        _, findings = analyze_source(code, "schedule.cpp")
        critical = [f for f in findings if f.vulnerability_type == "临界区未释放退出"]
        self.assertEqual(len(critical), 1)
        self.assertTrue(critical[0].execution_path)

    def test_detects_terminate_thread(self) -> None:
        code = "if(!TerminateThread(runPCB->hThis,1)){ exit(0); }"
        _, findings = analyze_source(code, "schedule.cpp")
        self.assertTrue(any(f.vulnerability_type == "架构级风险 API" for f in findings))

    def test_detects_nested_critical_sections_exit(self) -> None:
        code = """
        void f() {
            EnterCriticalSection(&cs_A);
            EnterCriticalSection(&cs_B);
            return;
            LeaveCriticalSection(&cs_B);
            LeaveCriticalSection(&cs_A);
        }
        """
        _, findings = analyze_source(code, "schedule.cpp")
        critical = [f for f in findings if f.vulnerability_type == "临界区未释放退出"]
        self.assertEqual(len(critical), 1)
        joined_path = "\n".join(critical[0].execution_path)
        self.assertIn("cs_A", joined_path)
        self.assertIn("cs_B", joined_path)

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

        findings = _parse_semgrep_json(json.dumps(payload), source_path=Path("Demo.java"), filename="Demo.java")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].filename, "Demo.java")
        self.assertEqual(findings[0].line_number, 12)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].vulnerability_type, "java.lang.security.demo")
        self.assertIn("Runtime.getRuntime().exec", findings[0].code_snippet)

    def test_default_html_path_is_inferred_from_input(self) -> None:
        from pathlib import Path

        self.assertEqual(_default_html_path([Path("samples/c_demo.c")]).name, "c_demo.html")
        self.assertEqual(_default_html_path([Path("a.c"), Path("b.java")]).name, "threadviper-report.html")


if __name__ == "__main__":
    unittest.main()
