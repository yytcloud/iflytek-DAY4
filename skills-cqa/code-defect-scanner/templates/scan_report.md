# 代码扫描报告

| 项目 | 值 |
|------|-----|
| 扫描路径 | `{{source_path}}` |
| 扫描文件数 | {{scanned_files}} |
| 跳过文件数 | {{skipped_files}} |
| 扫描耗时 | {{scan_time}} 秒 |
| 发现问题数 | **{{total_issues}}** |

---

## 问题统计

### 按严重级别

| 级别 | 数量 | 占比 |
|------|------|------|
| CRITICAL | **{{critical_count}}** | {{critical_percent}}% |
| HIGH | {{high_count}} | {{high_percent}}% |
| MEDIUM | {{medium_count}} | {{medium_percent}}% |
| LOW | {{low_count}} | {{low_percent}}% |
| INFO | {{info_count}} | {{info_percent}}% |

### 按分类

| 分类 | 数量 |
|------|------|
| 安全漏洞 | {{security_count}} |
| 代码缺陷 | {{defect_count}} |
| 代码异味 | {{smell_count}} |

---

## 严重问题 (CRITICAL)

> 需要立即修复的安全漏洞

## 高危问题 (HIGH)

> 可能导致运行时错误或安全问题

## 中等问题 (MEDIUM)

> 影响代码质量和可维护性

## 低级问题 (LOW) / 信息提示 (INFO)

---

## 修复优先级建议

1. **立即修复** (CRITICAL): {{critical_count}} 个问题
2. **尽快修复** (HIGH): {{high_count}} 个问题
3. **迭代内修复** (MEDIUM): {{medium_count}} 个问题
4. **逐步改进** (LOW/INFO): {{low_count + info_count}} 个问题

---

*本报告由 code-defect-scanner v1.0.0 自动生成*
*生成时间: {{generated_at}}*
