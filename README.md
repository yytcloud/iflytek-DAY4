# iflytek-DAY4

> 讯飞星火认知大模型 - Skill 工具集
>
> 基于讯飞星火大模型能力构建的三款实用智能分析 Skill，覆盖代码安全扫描、数据智能分析和简历岗位匹配三大场景。

---

## 项目简介

本项目包含三个独立的智能分析 Skill，每个 Skill 均提供完整的解析引擎、报告模板和示例数据，可独立运行也可集成到大模型工作流中。

## Skill 总览

| Skill | 目录 | 说明 | 核心能力 |
|-------|------|------|----------|
| 代码缺陷与安全扫描器 | `skills-cqa/code-defect-scanner/` | Python 代码静态安全审计 | SQL注入/命令注入检测、OWASP Top 10覆盖、代码异味识别 |
| 数据智能分析报告生成器 | `skills-dia-app/data-insight-reporter/` | 自动化数据分析与报告生成 | 描述性统计、异常值检测、趋势分析、相关性分析 |
| 简历智能解析与岗位匹配 | `skills-tm-dia/resume-job-matcher/` | 简历-JD多维度匹配分析 | 五维评分、差距诊断、优化建议、结构化报告 |

---

## 一、代码缺陷与安全扫描器

**路径：** `skills-cqa/code-defect-scanner/`

静态分析 Python 代码中的潜在缺陷、安全漏洞和代码异味，输出详细修复建议报告。

### 核心能力

- **安全漏洞检测**：覆盖 OWASP Top 10，支持 SQL 注入、命令注入、硬编码密钥、不安全反序列化等 14 条安全规则
- **代码缺陷检测**：空异常处理、不可达代码、资源泄露、未初始化变量等 10 条缺陷规则
- **代码异味检测**：过长函数、过深嵌套、魔法数字、过多参数等 7 条异味规则
- **AST 精确分析**：基于 Python 语法树进行精确的模式识别，支持嵌套结构分析
- **结构化报告**：输出 Markdown/JSON 格式报告，每个问题附带 CWE 编号和修复代码示例

### 文件结构

```
skills-cqa/code-defect-scanner/
├── SKILL.md                        # Skill 定义与使用说明
├── scripts/
│   └── scanner_engine.py           # 主扫描引擎（1400+ 行）
├── templates/
│   └── scan_report.md              # 扫描报告模板
└── examples/
    ├── vulnerable_code.py         # 含多种漏洞的示例代码
    └── scan_result.md              # 示例扫描结果报告
```

### 快速使用

```bash
# 扫描单个文件
python scripts/scanner_engine.py --source path/to/code.py

# 递归扫描目录，仅报告高危问题
python scripts/scanner_engine.py --source src/ --recursive --min-severity high

# 仅安全漏洞扫描（CI/CD 集成）
python scripts/scanner_engine.py --source src/ --category security --ci-mode
```

---

## 二、数据智能分析报告生成器

**路径：** `skills-dia-app/data-insight-reporter/`

自动分析 CSV/TSV/JSON 数据文件，生成包含关键指标、趋势分析、异常检测和相关性分析的结构化报告。

### 核心能力

- **智能数据加载**：自动检测文件编码（UTF-8/GBK/GB2312）和分隔符
- **描述性统计**：数值型（均值、中位数、标准差、偏度、峰度等）和分类型（频次、占比、基尼系数）统计
- **异常值检测**：支持 IQR 法、Z-Score 法、MAD 法、百分位法四种检测方法，含异常归因分析
- **趋势分析**：线性趋势识别、周期性检测、移动平均计算
- **相关性分析**：Pearson 和 Spearman 相关系数矩阵
- **数据质量评估**：完整性、一致性、准确性、时效性四维评分

### 文件结构

```
skills-dia-app/data-insight-reporter/
├── SKILL.md                        # Skill 定义与使用说明
├── scripts/
│   └── data_analyzer.py            # 数据分析引擎
├── templates/
│   └── report_template.md          # 分析报告模板
└── examples/
    ├── sample_data.csv             # 示例电商销售数据（30条）
    └── sample_report.md            # 示例分析报告
```

### 快速使用

```python
from scripts.data_analyzer import DataAnalyzer

analyzer = DataAnalyzer("data/sales.csv")
analyzer.load_data()
report = analyzer.generate_report(output_path="report.md")
```

```bash
# 命令行
python scripts/data_analyzer.py --file data.csv --output report.md
```

---

## 三、简历智能解析与岗位匹配

**路径：** `skills-tm-dia/resume-job-matcher/`

解析非结构化简历文本，与目标岗位 JD 进行五维度智能匹配分析，输出匹配度评分、差距诊断和优化建议。

### 核心能力

- **简历智能解析**：从 Markdown/纯文本中提取基本信息、教育经历、工作经历、技能清单、项目经历等
- **JD 要素提取**：解析岗位描述中的必须技能、加分技能、经验要求、学历要求、软实力要求
- **五维匹配评分**：技能匹配（30%）、经验匹配（25%）、项目经历（20%）、教育背景（15%）、软实力（10%）
- **技能近似匹配**：内置技术栈相似度表（如 Django/Flask = 0.7，MySQL/PostgreSQL = 0.8）
- **差距诊断与建议**：按高/中/低严重度分级，生成可操作的改进建议和行动计划
- **岗位类型预设**：内置技术岗、管理岗、设计岗、销售岗等权重方案

### 文件结构

```
skills-tm-dia/resume-job-matcher/
├── SKILL.md                        # Skill 定义与使用说明
├── scripts/
│   └── matcher_engine.py           # 匹配引擎（1450+ 行）
├── templates/
│   └── match_report.md            # 匹配报告模板
└── examples/
    ├── sample_resume.md          # 示例简历（高级后端开发工程师）
    ├── sample_jd.md               # 示例岗位JD
    └── sample_match_result.md     # 示例匹配结果报告
```

### 快速使用

```bash
# 命令行
python scripts/matcher_engine.py --resume resume.md --jd jd.md --output report.md

# 使用技术岗预设权重
python scripts/matcher_engine.py --resume resume.md --jd jd.md --preset tech
```

```python
from scripts.matcher_engine import ResumeJDMatcher

matcher = ResumeJDMatcher(preset="tech")
result = matcher.match(resume_text, jd_text)
print(f"匹配度: {result['overall_score']}%")
report = matcher.generate_report(result, output_path="report.md")
```

---

## 技术要求

- Python >= 3.8
- 无第三方依赖（全部使用 Python 标准库）

## 目录结构总览

```
iflytek-DAY4/
├── README.md                                # 本文件
├── skills-cqa/
│   └── code-defect-scanner/                 # 代码缺陷与安全扫描器
│       ├── SKILL.md
│       ├── scripts/scanner_engine.py
│       ├── templates/scan_report.md
│       └── examples/
├── skills-dia-app/
│   └── data-insight-reporter/               # 数据智能分析报告生成器
│       ├── SKILL.md
│       ├── scripts/data_analyzer.py
│       ├── templates/report_template.md
│       └── examples/
└── skills-tm-dia/
    └── resume-job-matcher/                  # 简历智能解析与岗位匹配
        ├── SKILL.md
        ├── scripts/matcher_engine.py
        ├── templates/match_report.md
        └── examples/
```

## 许可

本项目仅供学习和研究使用。