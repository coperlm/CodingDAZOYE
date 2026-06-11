# 🐍 项目代号：ThreadViper 开发计划书

项目定位： 一个无需编译即可运行的 Python 脚本，专门针对 C/C++ 源码，提供基于上下文的并发安全检测和危险内存 API 拦截，并给出修复建议。

## 阶段一：Vibe 启动与脚手架搭建 (Infrastructure)

你的目标是把代码文本干干净净地读进来，为后续的分析打好基础。

目标 1：源码读取与净化。 用 Python 写一个读取器。重点是写一个简单的正则或逻辑，剔除所有的 `//` 和 `//` 注释。这是极其重要的一步，防止工具对注释里的“strcpy”产生误报。
目标 2：数据结构设计。 定义一个统一的 `Vulnerability` 类，用来存放扫出来的漏洞。至少包含：`文件名`、`行号`、`漏洞类型`、`原始代码片段`、`修复建议`。
测试验收： 脚本能顺利读取 `schedule.cpp`，并在控制台打印出去除注释后的纯净代码。

## 阶段二：内存安全降维打击 (Memory & API Auditing)

针对测试用例中的硬伤进行定点爆破。

目标 1：危险字典构建。 建立一个 Python 字典，记录需要拦截的黑名单函数。结合你的测试用例，重点锁定 `strcpy` 。

目标 2：行级扫描引擎。 逐行比对净化后的代码，捕捉黑名单函数的调用。
突破极限点 (Auto-Remediation)： 不要只报错！在规则里写好映射。当扫到 `strcpy(newPcb->name,name);` 时 ，让工具自动生成建议：“检测到危险函数 `strcpy`，建议替换为安全的带边界检查函数 `strncpy(newPcb->name, name, sizeof(newPcb->name) - 1);`”。

## 阶段三：并发状态机追踪 (Concurrency State Tracking)

这是整个工具的灵魂，也是难度最高、最能秀肌肉的部分。

目标 1：定义状态机。 设置一个布尔变量 `in_critical_section = False`。
目标 2：上下文追踪。 遍历代码行：
遇到 `EnterCriticalSection`  -> 状态设为 `True`，并记录这行代码的行号。

遇到 `LeaveCriticalSection`  -> 状态设为 `False`。

目标 3：死锁与野线程捕获。
在 `in_critical_section == True` 的期间，如果扫描到了 `return`、`break` 或 `exit(0)`，直接爆出严重高危漏洞 (Critical)：“检测到临界区未释放即退出，可能导致全局死锁！” 。

全局搜索 `TerminateThread` 。这是一个在 C++ 中极其危险的强杀 API，会导致目标线程的栈内存和锁彻底泄漏。直接将其标记为架构级风险，并建议改用事件通知 (Event) 让线程优雅退出。

## 阶段四：终极视觉呈现 (The "Beyond Expectations" Output)

超越预期的关键在于“交付物的质感”。

目标 1：终端美化。 引入 Python 的 `Rich` 或 `Colorama` 库。让你的终端输出具有黑客电影般的质感：高危漏洞标红，修复建议标绿，输出格式整整齐齐。
目标 2：输出执行路径 (Execution Path)。 当发现临界区死锁时，打印出“污染链”：
> `[Line 230] 锁被获取: EnterCriticalSection(&cs_SaveInfo);`
> `[Line 231] 危险操作: Terminate thread failed!`
> `[Line 232] 异常退出: exit(0); (致命: 锁未释放!)`


目标 3：一键生成报告（选做，用于极限炫技）。 写个简单的模板，将收集到的 `Vulnerability` 列表渲染成一个 HTML 网页。

---

## 当前实现

- 主程序：`threadviper.py`
- 单元测试：`test_threadviper.py`

功能覆盖：
- ✅ 注释剔除（`//` 与 `//`）
- ✅ 统一漏洞结构体 `Vulnerability`（文件名、行号、类型、代码片段、修复建议等）
- ✅ 危险函数扫描（重点 `strcpy`）与自动修复建议
- ✅ 临界区状态跟踪（`EnterCriticalSection` / `LeaveCriticalSection`）
- ✅ 临界区内异常退出检测（`return` / `break` / `exit(...)`）
- ✅ `TerminateThread` 架构级风险检测
- ✅ 终端彩色输出（检测到 `rich` 时自动启用，未安装时自动降级）
- ✅ HTML 报告生成（可选）

### 使用方式

检测文件并输出到终端：

```bash
python threadviper.py 测试用例1.txt
```

检测并生成 HTML 报告：

```bash
python threadviper.py 测试用例1.txt --html report.html
```

运行测试：

```bash
python -m unittest -v
```

---

项目痛点：

传统的纯文本扫描很容易误报，难以发现多线程并发带来的隐藏风险

解决方案：

引入状态机追踪和动态上下文解析技术，针对并发死锁和内存安全进行处理

具体操作：

先把全部注释剥离掉（ `strip_comments` 函数）

搜索 `strcpy` 等危险函数
负责追踪线线程相关的高危操作