# 代码扫描报告

| 项目 | 值 |
|------|-----|
| 扫描路径 | `examples/vulnerable_code.py` |
| 扫描文件数 | 1 |
| 跳过文件数 | 0 |
| 扫描耗时 | 0.05 秒 |
| 发现问题数 | **24** |

---

## 问题统计

| 级别 | 数量 | 占比 |
|------|------|------|
| CRITICAL | **8** | 33% |
| HIGH | 4 | 17% |
| MEDIUM | 7 | 29% |
| LOW | 3 | 13% |
| INFO | 2 | 8% |

| 分类 | 数量 |
|------|------|
| 安全漏洞 | 12 |
| 代码缺陷 | 7 |
| 代码异味 | 5 |

---

## 严重问题 (CRITICAL)

> 需要立即修复的安全漏洞

### SEC-007: 硬编码密码
- **文件**: `examples/vulnerable_code.py`
- **行号**: 第 17 行
- **分类**: security (CWE-798)

### SEC-001: SQL 注入（f-string）
- **文件**: `examples/vulnerable_code.py`
- **行号**: 第 26 行
- **分类**: security (CWE-89)

### SEC-004: 命令注入（os.system）
- **文件**: `examples/vulnerable_code.py`
- **行号**: 第 48 行
- **分类**: security (CWE-78)

### SEC-006: 代码注入（eval）
- **文件**: `examples/vulnerable_code.py`
- **行号**: 第 59 行
- **分类**: security (CWE-95)

---

## 修复优先级建议

1. **立即修复** (CRITICAL): 8 个问题
2. **尽快修复** (HIGH): 4 个问题
3. **迭代内修复** (MEDIUM): 7 个问题
4. **逐步改进** (LOW/INFO): 5 个问题

---

*本报告由 code-defect-scanner v1.0.0 自动生成*
*生成时间: 2026-07-19 10:30:00*
