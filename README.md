# ThreadViper

ThreadViper 是一个面向 C、C++、Java、Python 的轻量级安全扫描工具。它结合了本地规则和 Semgrep 规则库，用来发现危险内存 API、并发临界区提前退出、危险线程终止调用，以及更多规则库覆盖到的安全问题。

实际上是编码安全实训的大作业~

## 它能做什么

- 扫描 C / C++ 源码中的 `strcpy`、临界区提前退出、`TerminateThread` 等问题。
- 扫描 Java / Python 源码中的命令注入、危险运行时调用、危险反序列化等 Semgrep 规则命中项。
- 自动剔除注释，减少注释文本导致的误报。
- 输出终端报告，支持 `rich` 时显示彩色表格。
- 默认生成 HTML 报告，便于共享与归档。
- 通过 `semgrep-rules` 子模块直接复用更完整的规则集，不再依赖样例手写判断。

## 环境与安装

这个项目使用 `uv` 管理依赖和运行环境。

### 1. 初始化依赖

```bash
uv sync
```

### 2. 运行测试

```bash
uv run python -m unittest -v
```

### 3. 运行扫描

```bash
uv run threadviper samples/c_demo.c
uv run threadviper samples/cpp_demo.cpp
uv run threadviper samples/java_demo.java
uv run threadviper samples/python_demo.py
```

如果你刚克隆仓库，还需要初始化子模块：

```bash
git submodule update --init --recursive
```

## 功能说明

### 本地规则

ThreadViper 先对源码做注释清理，然后执行本地规则扫描：

- `strcpy` 危险内存 API
- `EnterCriticalSection` / `LeaveCriticalSection` 状态追踪
- 临界区内的 `return`、`break`、`exit(...)`
- `TerminateThread` 高风险 API

### Semgrep 规则库

仓库中包含 `semgrep-rules` 子模块，它提供更完整的规则库。当前实现会按语言选择相应规则目录：

- C / C++：`semgrep-rules/c` 和 `semgrep-rules/generic`
- Java：`semgrep-rules/java` 和 `semgrep-rules/generic`
- Python：`semgrep-rules/python` 和 `semgrep-rules/generic`

Semgrep 的命中结果会被转换为统一的 `Vulnerability` 结构，再输出到终端和 HTML 报告中。

## 仓库结构

- `threadviper.py`：主程序。
- `test_threadviper.py`：单元测试。
- `samples/`：多语言样例输入。
- `semgrep-rules/`：Semgrep 规则子模块。
- `.github/workflows/ci.yml`：CI 工作流。
- `pyproject.toml`：`uv` / Python 项目配置。
- `uv.lock`：锁定后的依赖版本。

## 多语言样例

- `samples/c_demo.c`：C 示例，覆盖 `strcpy`、临界区退出和 `TerminateThread`。
- `samples/cpp_demo.cpp`：C++ 示例，覆盖相同的本地规则路径。
- `samples/java_demo.java`：Java 示例，覆盖 Semgrep 的 Java 规则。
- `samples/python_demo.py`：Python 示例，覆盖 Semgrep 的 Python 规则。

## 冗余文件说明

为了让仓库更干净，以下内容不应该作为源码保留：

- 根目录和 `samples/` 下的 HTML 报告，它们是运行时生成物。
- `requirements.txt`，现在已经被 `pyproject.toml` 和 `uv.lock` 替代。
- `threadviper.egg-info/`，这是构建元数据，不属于源码。

这些内容已经被忽略或清理，不需要手工维护。

## 开发建议

- 修改规则后先跑 `uv run python -m unittest -v`。
- 修改 Semgrep 接入后，再跑一次 Java 示例扫描验证输出。
- 如果你改了 `semgrep-rules` 子模块内容，记得提交子模块指针变化。

## 最常用命令

```bash
uv sync
uv run python -m unittest -v
uv run threadviper samples/c_demo.c
uv run threadviper samples/java_demo.java
uv run threadviper samples/java_demo.java --html report.html
```