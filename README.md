# ThreadViper

ThreadViper 是一个面向 C、C++、Java、Python 的轻量级安全扫描工具。它会先按语言剔除注释，再调用 `semgrep-rules` 子模块中的规则库进行检测，重点覆盖危险内存 API、命令注入、危险反序列化等安全问题。

这是一个编码安全实训项目，目标是把“能扫样例”升级成“能扫真实源码”。

## 功能

- 按语言清理注释，减少注释导致的误报。
- 扫描 C / C++ 中的危险字符串拷贝等问题。
- 扫描 Java / Python 中的命令注入、危险运行时调用、危险反序列化等问题。
- 终端输出检测结果，支持 `rich` 时显示彩色表格。
- 默认生成 HTML 报告，便于归档和共享。
- 复用 GitHub 引入的 `semgrep-rules` 规则仓库，不再依赖手写硬编码规则。
- 每条命中都会输出更具体的修复建议，例如命令执行改为参数数组、YAML 反序列化改为 `safe_load`、字符串拷贝改为带边界检查的接口。

## 安装与运行

这个项目使用 `uv` 管理依赖和运行环境。

### 安装依赖

```bash
uv sync
```

如果你是刚克隆仓库，还需要初始化子模块：

```bash
git submodule update --init --recursive
```

### 运行测试

```bash
uv run python -m unittest -v
```

### 运行扫描

```bash
uv run threadviper samples/c_demo.c
uv run threadviper samples/cpp_demo.cpp
uv run threadviper samples/java_demo.java
uv run threadviper samples/python_demo.py
uv run threadviper "测试用例1.txt"
uv run threadviper "测试用例2.txt"
```

默认情况下，ThreadViper 会在当前目录自动生成 HTML 报告。单文件扫描时，HTML 文件默认使用同名路径，例如 `samples/c_demo.html`；多文件扫描时，默认输出为 `threadviper-report.html`。你也可以显式传入 `--html` 指定路径。

## 检测流程

1. 先按语言识别源码类型。
2. 按对应语言剔除注释。
3. 将清理后的源码交给 Semgrep 扫描。
4. 将结果统一转换成 `Vulnerability` 结构。
5. 在命令行和 HTML 报告中输出检测结果。

终端不再输出去注释后的源码，只输出检测结果本身。

## 规则来源

仓库中包含 `semgrep-rules` 子模块，当前会按语言选择规则目录：

- C / C++：`semgrep-rules/c` 和 `semgrep-rules/generic`
- Java：`semgrep-rules/java` 和 `semgrep-rules/generic`
- Python：`semgrep-rules/python` 和 `semgrep-rules/generic`

如果未来继续扩展语言，只需要补对应的规则目录和语言识别逻辑即可。

## 样例

- `samples/c_demo.c`：C 示例。
- `samples/cpp_demo.cpp`：C++ 示例。
- `samples/java_demo.java`：Java 示例。
- `samples/python_demo.py`：Python 示例。
- 根目录下的 `测试用例1.txt` 和 `测试用例2.txt`：虽然扩展名是 `.txt`，但内容是 C++ 源码，工具会按内容识别并扫描。

## 仓库结构

- `threadviper.py`：主程序。
- `test_threadviper.py`：单元测试。
- `samples/`：演示样例。
- `semgrep-rules/`：Semgrep 规则子模块。
- `.github/workflows/ci.yml`：CI 工作流。
- `pyproject.toml`：`uv` / Python 项目配置。
- `uv.lock`：锁定依赖版本。
