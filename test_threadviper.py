import unittest

from threadviper import analyze_source, strip_comments


class ThreadViperTests(unittest.TestCase):
    def test_strip_comments_removes_single_and_multi_line(self) -> None:
        code = 'int a = 1; // comment\nchar* s = "http://x"; /* block */\nint b = 2;'
        clean = strip_comments(code)
        self.assertNotIn("// comment", clean)
        self.assertNotIn("block", clean)
        self.assertIn('"http://x"', clean)

    def test_detects_strcpy(self) -> None:
        code = "void f(){ strcpy(newPcb->name,name); }"
        _, findings = analyze_source(code, "schedule.cpp")
        self.assertTrue(any(f.vulnerability_type == "危险内存 API" for f in findings))

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


if __name__ == "__main__":
    unittest.main()
