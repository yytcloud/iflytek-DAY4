#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
代码缺陷与安全扫描器 (Code Defect & Security Scanner)

本脚本通过 AST 分析和正则匹配，静态扫描 Python 代码中的：
- 安全漏洞（SQL注入、命令注入、硬编码密钥等）
- 代码缺陷（空异常处理、不可达代码、资源泄露等）
- 代码异味（过长函数、过深嵌套、魔法数字等）

用法:
    python scanner_engine.py --source path/to/code.py
    python scanner_engine.py --source src/ --recursive --min-severity high
"""

import ast
import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ============================================================
# 数据结构定义
# ============================================================

class Severity(Enum):
    """严重级别"""
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'
    INFO = 'info'

    @property
    def weight(self) -> int:
        weights = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
        return weights[self.value]

    def __ge__(self, other):
        return self.weight >= other.weight


class Category(Enum):
    """扫描类别"""
    SECURITY = 'security'
    DEFECT = 'defect'
    SMELL = 'smell'


@dataclass
class ScanIssue:
    """扫描发现的问题"""
    rule_id: str
    rule_name: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    column_offset: int = 0
    description: str = ''
    cwe_id: str = ''
    fix_suggestion: str = ''
    code_snippet: str = ''
    fix_code: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id, 'rule_name': self.rule_name,
            'severity': self.severity.value, 'category': self.category.value,
            'file_path': self.file_path, 'line_number': self.line_number,
            'description': self.description, 'cwe_id': self.cwe_id,
            'fix_suggestion': self.fix_suggestion, 'code_snippet': self.code_snippet,
            'fix_code': self.fix_code,
        }


@dataclass
class ScanResult:
    """扫描结果"""
    source_path: str
    issues: List[ScanIssue] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    scan_time: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == Severity.INFO)

    @property
    def security_count(self) -> int:
        return sum(1 for i in self.issues if i.category == Category.SECURITY)

    @property
    def defect_count(self) -> int:
        return sum(1 for i in self.issues if i.category == Category.DEFECT)

    @property
    def smell_count(self) -> int:
        return sum(1 for i in self.issues if i.category == Category.SMELL)


# ============================================================
# SQL 注入检测器
# ============================================================

class SQLInjectionDetector:
    """SQL 注入漏洞检测器（基于 AST）"""

    SQL_KEYWORDS = re.compile(
        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC|UNION)\b',
        re.IGNORECASE
    )

    def detect(self, tree: ast.AST, source_lines: List[str],
               file_path: str) -> List[ScanIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                self._check_fstring_sql(node, source_lines, file_path, issues)
            elif isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Attribute) and node.func.attr == 'format'):
                    self._check_format_sql(node, source_lines, file_path, issues)
                elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                        sql_str = node.left.value
                        if self.SQL_KEYWORDS.search(sql_str):
                            issues.append(ScanIssue(
                                rule_id='SEC-003', rule_name='SQL 注入（% 格式化）',
                                severity=Severity.CRITICAL, category=Category.SECURITY,
                                file_path=file_path, line_number=node.lineno,
                                description='使用 % 格式化拼接 SQL 查询字符串，存在 SQL 注入风险',
                                cwe_id='CWE-89',
                                fix_suggestion='使用参数化查询替代字符串格式化',
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                                fix_code='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                            ))
        return issues

    def _check_fstring_sql(self, node: ast.JoinedStr, source_lines: List[str],
                           file_path: str, issues: List[ScanIssue]) -> None:
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                parts.append('{?}')
        full_str = ''.join(parts)
        if self.SQL_KEYWORDS.search(full_str):
            issues.append(ScanIssue(
                rule_id='SEC-001', rule_name='SQL 注入（f-string）',
                severity=Severity.CRITICAL, category=Category.SECURITY,
                file_path=file_path, line_number=node.lineno,
                description=f'使用 f-string 拼接 SQL 查询，存在 SQL 注入风险。检测到 SQL 关键字与变量插值。',
                cwe_id='CWE-89', fix_suggestion='使用参数化查询替代 f-string',
                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                fix_code='cursor.execute("SELECT * FROM users WHERE username = %s", (username,))',
            ))

    def _check_format_sql(self, node: ast.Call, source_lines: List[str],
                          file_path: str, issues: List[ScanIssue]) -> None:
        if node.func.value and isinstance(node.func.value, ast.Constant):
            sql_str = node.func.value.value
            if isinstance(sql_str, str) and self.SQL_KEYWORDS.search(sql_str):
                issues.append(ScanIssue(
                    rule_id='SEC-002', rule_name='SQL 注入（.format()）',
                    severity=Severity.CRITICAL, category=Category.SECURITY,
                    file_path=file_path, line_number=node.lineno,
                    description='使用 .format() 拼接 SQL 查询字符串，存在 SQL 注入风险',
                    cwe_id='CWE-89', fix_suggestion='使用参数化查询替代 .format()',
                    code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                    fix_code='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                ))


# ============================================================
# 命令注入检测器
# ============================================================

class CommandInjectionDetector:
    """命令注入漏洞检测器"""
    DANGEROUS_FUNCTIONS = {
        'os.system': {'cwe': 'CWE-78', 'severity': Severity.CRITICAL},
        'os.popen': {'cwe': 'CWE-78', 'severity': Severity.CRITICAL},
        'subprocess.call': {'cwe': 'CWE-78', 'severity': Severity.HIGH},
        'subprocess.run': {'cwe': 'CWE-78', 'severity': Severity.HIGH},
        'subprocess.Popen': {'cwe': 'CWE-78', 'severity': Severity.HIGH},
        'eval': {'cwe': 'CWE-95', 'severity': Severity.CRITICAL},
        'exec': {'cwe': 'CWE-95', 'severity': Severity.CRITICAL},
    }

    def detect(self, tree: ast.AST, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = self._get_call_name(node)
            if not func_name:
                continue
            if func_name in ('eval', 'exec'):
                has_var_arg = False
                if node.args and not isinstance(node.args[0], ast.Constant):
                    has_var_arg = True
                if has_var_arg:
                    info = self.DANGEROUS_FUNCTIONS[func_name]
                    issues.append(ScanIssue(
                        rule_id='SEC-006', rule_name=f'代码注入（{func_name}）',
                        severity=info['severity'], category=Category.SECURITY,
                        file_path=file_path, line_number=node.lineno,
                        description=f'{func_name}() 使用了非常量参数，存在代码注入风险',
                        cwe_id=info['cwe'],
                        fix_suggestion='避免使用 eval/exec，使用 ast.literal_eval 或其他安全替代方案',
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                        fix_code='# 使用 ast.literal_eval 替代 eval\nimport ast\nresult = ast.literal_eval(safe_input)',
                    ))
            elif func_name in ('os.system', 'os.popen'):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    info = self.DANGEROUS_FUNCTIONS[func_name]
                    issues.append(ScanIssue(
                        rule_id='SEC-004', rule_name=f'命令注入（{func_name}）',
                        severity=info['severity'], category=Category.SECURITY,
                        file_path=file_path, line_number=node.lineno,
                        description=f'{func_name}() 使用了非常量参数，存在命令注入风险',
                        cwe_id=info['cwe'],
                        fix_suggestion='使用 subprocess 并避免 shell=True，或使用 shlex.quote 转义参数',
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                        fix_code='import subprocess, shlex\nsubprocess.run(["ls", shlex.quote(user_input)], check=True)',
                    ))
            elif func_name in ('subprocess.call', 'subprocess.run', 'subprocess.Popen'):
                shell_true = False
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        shell_true = True; break
                if shell_true:
                    info = self.DANGEROUS_FUNCTIONS[func_name]
                    issues.append(ScanIssue(
                        rule_id='SEC-005', rule_name=f'命令注入（{func_name} shell=True）',
                        severity=info['severity'], category=Category.SECURITY,
                        file_path=file_path, line_number=node.lineno,
                        description=f'{func_name}(shell=True) 使用了 shell 模式，存在命令注入风险',
                        cwe_id=info['cwe'], fix_suggestion='避免 shell=True，使用列表形式传递命令和参数',
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                        fix_code='subprocess.run(["command", "arg1", "arg2"], check=True)',
                    ))
        return issues

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            parts.reverse()
            return '.'.join(parts)
        return None


# ============================================================
# 硬编码敏感信息检测器
# ============================================================

class HardcodedSecretDetector:
    """硬编码敏感信息检测器（基于正则）"""
    SECRET_PATTERNS: List[Tuple[str, str, str]] = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'](?!
            'SEC-007', '硬编码密码'),
        (r'(?i)(secret[_-]?key|secret)\s*=\s*["\'](?!
            'SEC-007', '硬编码密钥'),
        (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'](?!
            'SEC-008', '硬编码 API Key'),
        (r'(?i)(access[_-]?token|auth[_-]?token)\s*=\s*["\'](?!
            'SEC-008', '硬编码 Token'),
        (r'(?i)(database[_-]?url|db[_-]?url)\s*=\s*["\'][^"\']*(?:password|passwd|:)[^"\']*["\']',
         'SEC-007', '硬编码数据库连接串（含密码）'),
    ]
    EXCLUDE_PATTERNS = [r'YOUR_API_KEY_HERE', r'placeholder', r'example', r'xxx+', r'\*+', r'^[\'\"]$']

    def detect(self, source_code: str, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        for pattern_str, rule_id, rule_name in self.SECRET_PATTERNS:
            pattern = re.compile(pattern_str)
            for i, line in enumerate(source_lines, 1):
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('"""') or stripped.startswith("'''"):
                    continue
                match = pattern.search(line)
                if match:
                    matched_text = match.group()
                    excluded = False
                    for exc_pattern in self.EXCLUDE_PATTERNS:
                        if re.search(exc_pattern, matched_text, re.IGNORECASE):
                            excluded = True; break
                    if not excluded:
                        masked = self._mask_secret(matched_text)
                        issues.append(ScanIssue(
                            rule_id=rule_id, rule_name=rule_name,
                            severity=Severity.CRITICAL, category=Category.SECURITY,
                            file_path=file_path, line_number=i,
                            description=f'检测到硬编码的敏感信息: {masked}。硬编码的密钥和密码可能被提交到版本控制系统，造成安全泄露。',
                            cwe_id='CWE-798',
                            fix_suggestion='使用环境变量或配置管理工具管理敏感信息，不要将密钥写入源代码',
                            code_snippet=stripped,
                            fix_code='import os\nPASSWORD = os.environ.get("DB_PASSWORD")\n# 或使用 python-dotenv:\n# from dotenv import load_dotenv\n# load_dotenv()',
                        ))
        return issues

    def _mask_secret(self, text: str) -> str:
        eq_idx = text.find('=')
        if eq_idx >= 0:
            prefix = text[:eq_idx + 1].strip()
            value_part = text[eq_idx + 1:].strip()
            if len(value_part) >= 2 and value_part[0] in ('"', "'") and value_part[-1] in ('"', "'"):
                quote = value_part[0]
                return f'{prefix} {quote}***{quote}'
        return '***'


# ============================================================
# 代码缺陷检测器
# ============================================================

class DefectDetector:
    """代码缺陷检测器"""

    def detect(self, tree: ast.AST, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        issues.extend(self._detect_empty_except(tree, source_lines, file_path))
        issues.extend(self._detect_broad_except(tree, source_lines, file_path))
        issues.extend(self._detect_unreachable_code(tree, source_lines, file_path))
        issues.extend(self._detect_mutable_defaults(tree, source_lines, file_path))
        issues.extend(self._detect_duplicate_imports(tree, source_lines, file_path))
        issues.extend(self._detect_unused_variables(tree, source_lines, file_path))
        issues.extend(self._detect_unclosed_resources(tree, source_lines, file_path))
        return issues

    def _detect_empty_except(self, tree, source_lines, file_path):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    body_empty = len(handler.body) == 0
                    body_only_pass = len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)
                    body_only_ellipsis = (len(handler.body) == 1 and isinstance(handler.body[0], ast.Constant) and handler.body[0].value is ...)
                    if body_empty or body_only_pass or body_only_ellipsis:
                        exc_type = 'Exception' if handler.type is None else self._get_name(handler.type)
                        issues.append(ScanIssue(rule_id='DEF-001', rule_name='空 except 块（异常吞没）',
                            severity=Severity.HIGH, category=Category.DEFECT, file_path=file_path,
                            line_number=handler.lineno,
                            description=f'except {exc_type} 块为空或仅包含 pass，异常被静默吞没。',
                            fix_suggestion='至少记录异常日志，或处理特定的异常类型',
                            code_snippet=source_lines[handler.lineno - 1].strip() if handler.lineno <= len(source_lines) else '',
                            fix_code=f'except {exc_type} as e:\n    logger.error(f"操作失败: {{e}}")\n    raise'))
        return issues

    def _detect_broad_except(self, tree, source_lines, file_path):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type is None and not (len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)):
                        issues.append(ScanIssue(rule_id='DEF-002', rule_name='过宽异常捕获（裸 except）',
                            severity=Severity.MEDIUM, category=Category.DEFECT, file_path=file_path,
                            line_number=handler.lineno,
                            description='使用裸 except: 捕获所有异常，包括 KeyboardInterrupt 和 SystemExit。',
                            fix_suggestion='指定需要捕获的具体异常类型，如 except ValueError:',
                            code_snippet=source_lines[handler.lineno - 1].strip() if handler.lineno <= len(source_lines) else '',
                            fix_code='except (ValueError, TypeError) as e:\n    logger.warning(f"处理参数错误: {e}")'))
        return issues

    def _detect_unreachable_code(self, tree, source_lines, file_path):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for i, stmt in enumerate(node.body):
                    if i == 0: continue
                    prev = node.body[i - 1]
                    if isinstance(prev, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                            issues.append(ScanIssue(rule_id='DEF-004', rule_name='不可达代码',
                                severity=Severity.MEDIUM, category=Category.DEFECT, file_path=file_path,
                                line_number=stmt.lineno,
                                description=f'第 {stmt.lineno} 行的代码不可达，它位于 return/raise/break/continue 语句之后。',
                                fix_suggestion='移除不可达的代码，或调整控制流逻辑',
                                code_snippet=source_lines[stmt.lineno - 1].strip() if stmt.lineno <= len(source_lines) else '',
                                fix_code='# 删除不可达代码'))
                            break
        return issues

    def _detect_mutable_defaults(self, tree, source_lines, file_path):
        issues = []
        mutable_types = (ast.List, ast.Dict, ast.Set)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults:
                    if isinstance(default, mutable_types):
                        issues.append(ScanIssue(rule_id='DEF-008', rule_name='可变默认参数',
                            severity=Severity.MEDIUM, category=Category.DEFECT, file_path=file_path,
                            line_number=node.lineno,
                            description=f'函数 {node.name} 使用可变对象（{type(default).__name__}）作为默认参数。',
                            fix_suggestion='使用 None 作为默认值，在函数体内创建新对象',
                            code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                            fix_code='def func(arg=None):\n    if arg is None:\n        arg = []'))
        return issues

    def _detect_duplicate_imports(self, tree, source_lines, file_path):
        issues = []
        seen_imports: Dict[str, int] = {}
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    key = alias.name
                    if key in seen_imports:
                        issues.append(ScanIssue(rule_id='DEF-006', rule_name='重复导入',
                            severity=Severity.LOW, category=Category.DEFECT, file_path=file_path,
                            line_number=node.lineno,
                            description=f'模块 {key} 在第 {seen_imports[key]} 行已导入，此处重复导入',
                            fix_suggestion='移除重复的 import 语句',
                            code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ''))
                    else:
                        seen_imports[key] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        key = f"{node.module}.{alias.name}"
                        if key in seen_imports:
                            issues.append(ScanIssue(rule_id='DEF-006', rule_name='重复导入',
                                severity=Severity.LOW, category=Category.DEFECT, file_path=file_path,
                                line_number=node.lineno,
                                description=f'{key} 在第 {seen_imports[key]} 行已导入，此处重复导入',
                                fix_suggestion='移除重复的 import 语句',
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else ''))
                        else:
                            seen_imports[key] = node.lineno
        return issues

    def _detect_unused_variables(self, tree, source_lines, file_path):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned_vars: Dict[str, int] = {}
                used_names: Set[str] = set()
                for child in ast.walk(node):
                    if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and not target.id.startswith('_'):
                                assigned_vars[target.id] = child.lineno
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        used_names.add(child.id)
                for var_name, line_no in assigned_vars.items():
                    if var_name not in used_names:
                        issues.append(ScanIssue(rule_id='DEF-007', rule_name='未使用的变量',
                            severity=Severity.LOW, category=Category.DEFECT, file_path=file_path,
                            line_number=line_no,
                            description=f'变量 "{var_name}" 被赋值后未被使用',
                            fix_suggestion='移除未使用的变量，或使用 _ 前缀表示有意忽略',
                            code_snippet=source_lines[line_no - 1].strip() if line_no <= len(source_lines) else ''))
        return issues

    def _detect_unclosed_resources(self, tree, source_lines, file_path):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.With): continue
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func_name = self._get_call_name_simple(node.value)
                if func_name == 'open':
                    issues.append(ScanIssue(rule_id='DEF-005', rule_name='资源未安全关闭',
                        severity=Severity.MEDIUM, category=Category.DEFECT, file_path=file_path,
                        line_number=node.lineno,
                        description='使用 open() 但未使用 with 语句，文件资源可能不会被正确关闭',
                        fix_suggestion='使用 with 语句确保资源自动释放',
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                        fix_code='with open("file.txt", "r") as f:\n    content = f.read()'))
        return issues

    def _get_name(self, node) -> Optional[str]:
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _get_call_name_simple(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name): return node.func.id
        elif isinstance(node.func, ast.Attribute): return node.func.attr
        return None


# ============================================================
# 代码异味检测器
# ============================================================

class CodeSmellDetector:
    """代码异味检测器"""

    def detect(self, tree: ast.AST, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        issues.extend(self._detect_long_functions(tree, source_lines, file_path))
        issues.extend(self._detect_too_many_params(tree, source_lines, file_path))
        issues.extend(self._detect_deep_nesting(tree, source_lines, file_path))
        issues.extend(self._detect_long_lines(source_lines, file_path))
        issues.extend(self._detect_magic_numbers(tree, source_lines, file_path))
        return issues

    def _detect_long_functions(self, tree, source_lines, file_path):
        issues = []
        max_lines = 50
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_lines = node.end_lineno - node.lineno + 1 if hasattr(node, 'end_lineno') else 0
                if func_lines > max_lines:
                    issues.append(ScanIssue(rule_id='SML-001', rule_name='过长函数',
                        severity=Severity.MEDIUM, category=Category.SMELL, file_path=file_path,
                        line_number=node.lineno,
                        description=f'函数 {node.name} 有 {func_lines} 行，超过建议上限 {max_lines} 行。',
                        fix_suggestion='将函数拆分为多个小函数，每个函数只做一件事',
                        code_snippet=f'def {node.name}(...):  # {func_lines} 行'))
        return issues

    def _detect_too_many_params(self, tree, source_lines, file_path):
        issues = []
        max_params = 7
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                param_count = len(node.args.args) + len(node.args.kwonlyargs)
                if param_count > 0 and node.args.args[0].arg in ('self', 'cls'): param_count -= 1
                if param_count > max_params:
                    issues.append(ScanIssue(rule_id='SML-003', rule_name='过多参数',
                        severity=Severity.MEDIUM, category=Category.SMELL, file_path=file_path,
                        line_number=node.lineno,
                        description=f'函数 {node.name} 有 {param_count} 个参数，超过建议上限 {max_params} 个。',
                        fix_suggestion='将相关参数封装为数据类或字典，或使用 Builder 模式',
                        code_snippet=f'def {node.name}({", ".join(a.arg for a in node.args.args)})'))
        return issues

    def _detect_deep_nesting(self, tree, source_lines, file_path):
        issues = []
        max_depth = 4
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                max_nest = self._get_max_nesting(node, 0)
                if max_nest > max_depth:
                    issues.append(ScanIssue(rule_id='SML-002', rule_name='过深嵌套',
                        severity=Severity.MEDIUM, category=Category.SMELL, file_path=file_path,
                        line_number=node.lineno,
                        description=f'函数 {node.name} 的最大嵌套深度为 {max_nest} 层，超过建议上限 {max_depth} 层。',
                        fix_suggestion='使用 early return 减少嵌套，或将嵌套逻辑提取为独立函数',
                        code_snippet=f'def {node.name}(...):  # 嵌套深度 {max_nest}'))
        return issues

    def _get_max_nesting(self, node, current_depth: int) -> int:
        nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)
        max_depth = current_depth
        for child in ast.iter_child_nodes(node):
            if isinstance(child, nesting_nodes):
                max_depth = max(max_depth, self._get_max_nesting(child, current_depth + 1))
            elif isinstance(child, ast.ExceptHandler):
                max_depth = max(max_depth, self._get_max_nesting(child, current_depth + 1))
            elif not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                max_depth = max(max_depth, self._get_max_nesting(child, current_depth))
        return max_depth

    def _detect_long_lines(self, source_lines, file_path):
        issues = []
        max_length = 120
        for i, line in enumerate(source_lines, 1):
            stripped = line.rstrip()
            if not stripped or stripped.startswith('#'): continue
            if len(stripped) > max_length:
                issues.append(ScanIssue(rule_id='SML-007', rule_name='过长行',
                    severity=Severity.INFO, category=Category.SMELL, file_path=file_path,
                    line_number=i,
                    description=f'行长度为 {len(stripped)} 字符，超过建议上限 {max_length} 字符。',
                    fix_suggestion='将长行拆分为多行，使用括号续行',
                    code_snippet=stripped[:80] + '...'))
        return issues

    def _detect_magic_numbers(self, tree, source_lines, file_path):
        issues = []
        allowed_numbers = {0, 1, -1, 2, 10, 100, 1000, 0.0, 1.0, 0.5}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
                if node.value in allowed_numbers: continue
                if isinstance(node.value, int) and abs(node.value) > 10000: continue
                if isinstance(node.value, float) and abs(node.value) < 0.01: continue
                if node.lineno <= len(source_lines):
                    line = source_lines[node.lineno - 1].strip()
                    if line.startswith('#') or line.startswith('"""') or line.startswith("'''"): continue
                    issues.append(ScanIssue(rule_id='SML-005', rule_name='魔法数字',
                        severity=Severity.INFO, category=Category.SMELL, file_path=file_path,
                        line_number=node.lineno,
                        description=f'使用了魔法数字 {node.value}，建议提取为命名常量以提高可读性。',
                        fix_suggestion='将数字提取为有意义的常量名',
                        code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                        fix_code=f'MAX_RETRIES = {int(node.value)}  # 定义为模块级常量'))
        return issues[:10]

    def _get_call_name_simple(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name): return node.func.id
        elif isinstance(node.func, ast.Attribute): return node.func.attr
        return None


# ============================================================
# 调试代码检测器
# ============================================================

class DebugCodeDetector:
    """调试代码残留检测器"""
    DEBUG_PATTERNS: List[Tuple[str, str, str, Severity]] = [
        (r'pdb\.set_trace\(\)', 'SEC-011', '调试断点残留', Severity.MEDIUM),
        (r'breakpoint\(\)', 'SEC-011', '调试断点残留', Severity.MEDIUM),
        (r'import\s+pdb', 'SEC-011', '调试模块导入', Severity.LOW),
        (r'pprint\.pprint\(', 'SEC-011', '调试打印残留', Severity.LOW),
        (r'\bprint\s*\(\s*f?["\'].*(?:password|secret|token|key)', 'SEC-011', '敏感信息打印', Severity.HIGH),
        (r'logger\.debug\s*\(\s*f?["\'].*(?:password|secret|token|key)', 'SEC-009', '敏感信息写入日志', Severity.MEDIUM),
    ]

    def detect(self, source_code: str, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        for pattern_str, rule_id, rule_name, severity in self.DEBUG_PATTERNS:
            pattern = re.compile(pattern_str)
            for i, line in enumerate(source_lines, 1):
                if pattern.search(line):
                    issues.append(ScanIssue(
                        rule_id=rule_id, rule_name=rule_name, severity=severity,
                        category=Category.SECURITY, file_path=file_path, line_number=i,
                        description=f'检测到调试代码残留: {rule_name}。调试代码不应出现在生产环境。',
                        cwe_id='CWE-489' if '断点' in rule_name else 'CWE-778',
                        fix_suggestion='移除调试代码，或使用条件判断（如 if settings.DEBUG:）',
                        code_snippet=line.strip()))
        return issues


# ============================================================
# SSL 安全检测器
# ============================================================

class SSLSecurityDetector:
    """SSL/TLS 安全检测器"""

    def detect(self, tree: ast.AST, source_lines: List[str], file_path: str) -> List[ScanIssue]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == 'verify' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        func_name = ''
                        if isinstance(node.func, ast.Name): func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute): func_name = node.func.attr
                        if func_name in ('get', 'post', 'put', 'delete', 'patch', 'request', 'requests'):
                            issues.append(ScanIssue(rule_id='SEC-014', rule_name='SSL 证书验证禁用',
                                severity=Severity.HIGH, category=Category.SECURITY,
                                file_path=file_path, line_number=node.lineno,
                                description=f'{func_name}(verify=False) 禁用了 SSL 证书验证，容易遭受中间人攻击。',
                                cwe_id='CWE-295',
                                fix_suggestion='启用 SSL 验证，或为特定场景指定 CA 证书路径',
                                code_snippet=source_lines[node.lineno - 1].strip() if node.lineno <= len(source_lines) else '',
                                fix_code='requests.get(url, verify=True)  # 或 verify="/path/to/ca-bundle.crt"'))
        return issues


# ============================================================
# 报告渲染器
# ============================================================

class MarkdownReportRenderer:
    """Markdown 格式的扫描报告渲染器"""
    def render(self, result: ScanResult) -> str:
        lines = ['# 代码扫描报告', '', '| 项目 | 值 |', '|------|-----|',
                 f'| 扫描路径 | `{result.source_path}` |',
                 f'| 扫描文件数 | {result.scanned_files} |',
                 f'| 跳过文件数 | {result.skipped_files} |',
                 f'| 扫描耗时 | {result.scan_time:.2f} 秒 |',
                 f'| 发现问题数 | **{len(result.issues)}** |', '',
                 '## 问题统计', '', '| 级别 | 数量 |', '|------|------|',
                 f'| CRITICAL | **{result.critical_count}** |',
                 f'| HIGH | {result.high_count} |',
                 f'| MEDIUM | {result.medium_count} |',
                 f'| LOW | {result.low_count} |',
                 f'| INFO | {result.info_count} |', '',
                 '| 分类 | 数量 |', '|------|------|',
                 f'| 安全漏洞 | {result.security_count} |',
                 f'| 代码缺陷 | {result.defect_count} |',
                 f'| 代码异味 | {result.smell_count} |', '']
        if not result.issues:
            lines.extend(['## 扫描结果', '', '**未发现问题，代码质量良好。**', ''])
            return '\n'.join(lines)
        sorted_issues = sorted(result.issues, key=lambda i: (-i.severity.weight, i.line_number))
        severity_groups = {
            Severity.CRITICAL: ('## 严重问题 (CRITICAL)', '需要立即修复的安全漏洞'),
            Severity.HIGH: ('## 高危问题 (HIGH)', '可能导致运行时错误或安全问题'),
            Severity.MEDIUM: ('## 中等问题 (MEDIUM)', '影响代码质量和可维护性'),
            Severity.LOW: ('## 低级问题 (LOW)', '代码风格和最佳实践建议'),
            Severity.INFO: ('## 信息提示 (INFO)', '优化建议'),
        }
        for severity, (title, desc) in severity_groups.items():
            group_issues = [i for i in sorted_issues if i.severity == severity]
            if not group_issues: continue
            lines.extend([title, '', f'> {desc}', ''])
            for issue in group_issues:
                lines.extend([f'### {issue.rule_id}: {issue.rule_name}', '',
                    f'- **文件**: `{issue.file_path}`',
                    f'- **行号**: 第 {issue.line_number} 行',
                    f'- **分类**: {issue.category.value}' + (f' ({issue.cwe_id})' if issue.cwe_id else ''),
                    f'- **描述**: {issue.description}', ''])
                if issue.code_snippet:
                    lines.extend(['**问题代码**:', '```python', issue.code_snippet, '```', ''])
                if issue.fix_suggestion:
                    lines.extend([f'**修复建议**: {issue.fix_suggestion}', ''])
                if issue.fix_code:
                    lines.extend(['**修复示例**:', '```python', issue.fix_code, '```', ''])
                lines.extend(['---', ''])
        lines.extend(['*本报告由 code-defect-scanner v1.0.0 自动生成*',
                     f'*生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*', ''])
        return '\n'.join(lines)


class JSONReportRenderer:
    """JSON 格式的扫描报告渲染器"""
    def render(self, result: ScanResult) -> str:
        data = {
            'source_path': result.source_path, 'scanned_files': result.scanned_files,
            'skipped_files': result.skipped_files, 'scan_time': result.scan_time,
            'summary': {'total': len(result.issues), 'critical': result.critical_count,
                'high': result.high_count, 'medium': result.medium_count, 'low': result.low_count,
                'info': result.info_count, 'security': result.security_count,
                'defect': result.defect_count, 'smell': result.smell_count},
            'issues': [issue.to_dict() for issue in result.issues],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


# ============================================================
# 主控制器
# ============================================================

def scan_file(file_path: str, categories: List[Category], min_severity: Severity) -> List[ScanIssue]:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
    except (IOError, UnicodeDecodeError): return []
    source_lines = source_code.split('\n')
    try: tree = ast.parse(source_code)
    except SyntaxError: return []
    all_issues = []
    if Category.SECURITY in categories:
        all_issues.extend(SQLInjectionDetector().detect(tree, source_lines, file_path))
        all_issues.extend(CommandInjectionDetector().detect(tree, source_lines, file_path))
        all_issues.extend(HardcodedSecretDetector().detect(source_code, source_lines, file_path))
        all_issues.extend(DebugCodeDetector().detect(source_code, source_lines, file_path))
        all_issues.extend(SSLSecurityDetector().detect(tree, source_lines, file_path))
    if Category.DEFECT in categories:
        all_issues.extend(DefectDetector().detect(tree, source_lines, file_path))
    if Category.SMELL in categories:
        all_issues.extend(CodeSmellDetector().detect(tree, source_lines, file_path))
    all_issues = [i for i in all_issues if i.severity >= min_severity]
    return all_issues


def main():
    parser = argparse.ArgumentParser(description='代码缺陷与安全扫描器 - 静态分析代码中的缺陷、漏洞和异味',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--source', required=True, help='源代码文件或目录路径')
    parser.add_argument('--output', default='./scan_report.md', help='报告输出路径 (默认: ./scan_report.md)')
    parser.add_argument('--format', choices=['markdown', 'json'], default='markdown', help='报告格式 (默认: markdown)')
    parser.add_argument('--category', choices=['all', 'defect', 'security', 'smell'], default='all', help='扫描类别 (默认: all)')
    parser.add_argument('--min-severity', choices=['info', 'low', 'medium', 'high', 'critical'], default='low', help='最低报告级别 (默认: low)')
    parser.add_argument('--ci-mode', action='store_true', help='CI 模式：发现 high/critical 时以非零退出码退出')
    parser.add_argument('--recursive', action='store_true', help='递归扫描子目录')
    parser.add_argument('--verbose', '-v', action='store_true', help='显示详细扫描日志')
    args = parser.parse_args()
    category_map = {'all': [Category.SECURITY, Category.DEFECT, Category.SMELL],
        'defect': [Category.DEFECT], 'security': [Category.SECURITY], 'smell': [Category.SMELL]}
    categories = category_map[args.category]
    min_severity = Severity(args.min_severity)
    if not os.path.exists(args.source):
        print(f"[错误] 路径不存在: {args.source}"); sys.exit(1)
    import time
    start_time = time.time()
    print(f"代码缺陷与安全扫描器 v1.0.0")
    print(f"类别: {args.category} | 最低级别: {args.min_severity}")
    print(f"{'='*60}")
    source_files = []
    if os.path.isfile(args.source): source_files.append(args.source)
    else:
        pattern = '**/*.py' if args.recursive else '*.py'
        source_files = [str(f) for f in Path(args.source).glob(pattern)
                        if f.name != '__init__.py' and 'test' not in f.name.lower()]
    result = ScanResult(source_path=args.source)
    all_issues = []
    for f in source_files:
        if args.verbose: print(f"  扫描: {f}")
        issues = scan_file(f, categories, min_severity)
        all_issues.extend(issues)
        result.scanned_files += 1
    result.issues = all_issues
    result.scan_time = time.time() - start_time
    if args.format == 'json': renderer = JSONReportRenderer()
    else: renderer = MarkdownReportRenderer()
    content = renderer.render(result)
    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"\n扫描完成:")
    print(f"  文件: {result.scanned_files} 个")
    print(f"  问题: {len(result.issues)} 个")
    print(f"    CRITICAL: {result.critical_count}")
    print(f"    HIGH:     {result.high_count}")
    print(f"    MEDIUM:   {result.medium_count}")
    print(f"    LOW:      {result.low_count}")
    print(f"    INFO:     {result.info_count}")
    print(f"  报告: {args.output}")
    if args.ci_mode and (result.critical_count > 0 or result.high_count > 0):
        print(f"\n[CI 失败] 发现 {result.critical_count} 个严重问题和 {result.high_count} 个高危问题")
        sys.exit(1)


if __name__ == '__main__':
    main()
