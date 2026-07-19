---
name: codedefectscanner
description: "静态分析Python代码中的潜在缺陷、安全漏洞和代码异味，输出详细修复建议报告。当用户需要代码扫描、安全审计、代码质量检查、缺陷检测、安全漏洞扫描、代码审查辅助、代码规范检查时触发。支持OWASP Top 10和CWE标准分类。"
version: "1.0.0"
---

# 代码缺陷与安全扫描器 (Code Defect & Security Scanner)

## 一、触发条件与适用场景

### 触发关键词
- "扫描代码" / "代码扫描" / "静态分析"
- "安全漏洞" / "安全扫描" / "安全审计"
- "代码质量" / "代码审查" / "代码检查"
- "缺陷检测" / "Bug 检测" / "代码缺陷"
- "代码异味" / "Code Smell" / "坏味道"
- "SQL注入" / "XSS" / "安全检查"
- "代码规范" / "规范检查" / "代码风格"

### 适用场景
1. **代码提交前预检**：在 Git 提交或 PR 创建前进行静态扫描，提前发现潜在问题
2. **安全审计**：定期对项目进行安全漏洞扫描，满足合规要求
3. **代码质量评估**：量化评估代码质量，识别技术债务
4. **新人代码审查**：辅助 Code Review，确保不引入安全漏洞和常见缺陷
5. **遗留代码治理**：对存量代码进行全面扫描，制定修复优先级
6. **CI/CD 质量门禁**：在流水线中设置质量门槛，阻止低质量代码合入

### 不适用场景
- 运行时性能分析（需 cProfile、py-spy 等动态分析工具）
- 依赖漏洞扫描（需 Safety、pip-audit 等专门工具）
- 类型检查（需 mypy、pyright 等类型检查器）
- 代码格式化检查（需 Black、Ruff 等格式化工具）
- 代码复杂度度量（需 radon、lizard 等专门工具）

---

## 二、核心能力

### 2.1 缺陷检测引擎

#### 语法与运行时缺陷
| 缺陷类型 | 检测规则 | 严重级别 |
|---------|---------|----------|
| 未处理异常 | `except: pass` 或空 except 块 | HIGH |
| 变量未使用 | 赋值后未被引用的变量 | LOW |
| 不可达代码 | return/break/raise 后的语句 | MEDIUM |
| 重复导入 | 同一模块被 import 多次 | LOW |
| 未关闭的资源 | open() 无 with 语句且未 close() | MEDIUM |
| 空字典/列表迭代 | 对可能为空的容器直接迭代 | LOW |
| 硬编码密码 | 字符串中包含 password/secret/key 模式 | CRITICAL |
| 未初始化变量 | 使用前可能未赋值的变量 | HIGH |

### 2.2 安全漏洞检测

#### OWASP Top 10 覆盖
| OWASP 类别 | CWE 编号 | 检测内容 |
|-----------|---------|----------|
| A01: 权限控制失效 | CWE-285 | 硬编码权限检查、缺少认证装饰器 |
| A02: 加密机制失败 | CWE-798 | 硬编码密钥/密码/Token |
| A03: 注入 | CWE-89, CWE-78 | SQL 拼接、命令拼接、格式化字符串注入 |
| A04: 不安全设计 | CWE-209 | 异常信息泄露、调试信息输出 |
| A05: 安全配置错误 | CWE-16 | Debug 模式开启、CORS 全开 |
| A06: 脆弱组件 | CWE-1104 | 使用已知不安全的函数 |
| A07: 认证失败 | CWE-798 | 弱密码策略、默认凭证 |
| A08: 数据完整性失败 | CWE-345 | 不安全的反序列化 |
| A09: 日志监控不足 | CWE-778 | 敏感信息写入日志 |
| A10: SSRF | CWE-918 | 用户控制的 URL 请求 |

---

## 三、操作步骤

### 步骤 1：环境准备
```bash
ls -la path/to/source_code.py
python scripts/scanner_engine.py --help
```

### 步骤 2：执行扫描
```bash
python scripts/scanner_engine.py --source path/to/source_code.py
python scripts/scanner_engine.py --source src/ --recursive
python scripts/scanner_engine.py --source src/ --output report.md --format markdown
python scripts/scanner_engine.py --source src/ --category security
python scripts/scanner_engine.py --source src/ --min-severity high
```

### 步骤 3：查看报告
扫描完成后，打开输出的报告文件。报告按严重级别排序，每个问题包含：
- 问题描述和位置
- 严重级别和分类
- 修复建议和示例代码

### 步骤 4：修复与验证
1. 按严重级别从高到低逐项修复
2. 修复后重新扫描验证
3. 确认问题已解决后提交代码

---

## 四、引用支撑文件

### 核心脚本
| 文件路径 | 说明 |
|---------|------|
| `scripts/scanner_engine.py` | 主扫描引擎，包含 AST 分析、安全规则检测、报告渲染等全部逻辑 |

### 模板文件
| 文件路径 | 说明 |
|---------|------|
| `templates/scan_report.md` | 扫描报告模板，定义报告结构、问题展示格式和统计摘要 |

### 示例文件
| 文件路径 | 说明 |
|---------|------|
| `examples/vulnerable_code.py` | 包含多种缺陷和安全漏洞的示例代码，用于展示扫描效果 |
| `examples/scan_result.md` | 对示例代码的扫描结果报告，展示报告格式和内容 |

---

## 五、完整命令行参数

```
usage: scanner_engine.py [-h] --source SOURCE [--output OUTPUT]
                         [--format {markdown,json}]
                         [--category {all,defect,security,smell}]
                         [--min-severity {info,low,medium,high,critical}]
                         [--ci-mode] [--recursive] [--verbose]

必选参数:
  --source SOURCE         源代码文件或目录路径

可选参数:
  -h, --help              显示帮助信息
  --output OUTPUT         报告输出路径 (默认: ./scan_report.md)
  --format {markdown,json}  报告格式 (默认: markdown)
  --category {all,defect,security,smell}  扫描类别 (默认: all)
  --min-severity {info,low,medium,high,critical}  最低报告严重级别 (默认: low)
  --ci-mode               CI 模式：发现 high/critical 时以非零退出码退出
  --recursive             递归扫描子目录
  --verbose, -v           显示详细扫描日志
```

---

## 六、已知限制

1. **语言支持**：当前版本仅支持 Python 代码的静态分析
2. **跨文件分析**：不进行跨文件的调用链分析
3. **类型推断**：不执行类型推断
4. **框架感知**：对 Web 框架的安全上下文理解有限
5. **误报率**：部分规则可能产生误报
6. **第三方库**：不扫描第三方依赖中的漏洞

---

## 七、版本历史

| 版本 | 日期 | 变更说明 |
|------|------|----------|
| 1.0.0 | 2026-07-19 | 初始版本 |
