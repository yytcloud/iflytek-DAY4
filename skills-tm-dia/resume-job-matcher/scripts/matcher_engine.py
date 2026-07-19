#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简历智能解析与岗位匹配引擎 (Resume-Job Matcher Engine)

功能概述：
1. 简历文本解析 - 从非结构化文本中提取简历结构化信息
2. JD要素提取 - 解析岗位描述中的核心要求
3. 多维度匹配分析 - 技能/经验/教育/项目/软实力五维评分
4. 差距诊断与优化建议 - 识别差距并生成改进建议
5. 报告生成 - 输出结构化Markdown匹配报告

使用方法：
  命令行: python matcher_engine.py --resume resume.md --jd jd.md --output report.md
  模块化: from matcher_engine import ResumeJDMatcher

作者: 人才匹配与发展智能辅助 Skill 包
版本: 1.0.0
"""

import re
import json
import os
import sys
import argparse
import math
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any


# =============================================================================
# 工具函数
# =============================================================================

def normalize_text(text: str) -> str:
    """
    文本标准化处理：
    - 去除多余空白字符
    - 统一换行符
    - 去除Markdown标记符号（保留结构）
    """
    if not text:
        return ""
    # 统一换行符
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # 将连续多个空行压缩为单个
    text = re.sub(r'\n{3,}', '\n\n', text)
    # 去除行首行尾空白
    lines = [line.strip() for line in text.split('\n')]
    text = '\n'.join(lines)
    # 去除Markdown粗体/斜体标记但保留文字
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    return text.strip()


def extract_sections(text: str) -> Dict[str, str]:
    """
    按Markdown标题层级提取文本章节
    返回 {章节标题: 章节内容} 的字典
    """
    sections = {}
    # 匹配Markdown标题 (# ## ### 等)
    pattern = r'^(#{1,4}\s+.+)$'
    lines = text.split('\n')
    current_title = "概述"
    current_content = []

    for line in lines:
        match = re.match(pattern, line.strip())
        if match:
            # 保存上一个章节
            if current_content:
                sections[current_title] = '\n'.join(current_content).strip()
            current_title = line.strip().lstrip('#').strip()
            current_content = []
        else:
            current_content.append(line)

    # 保存最后一个章节
    if current_content:
        sections[current_title] = '\n'.join(current_content).strip()

    return sections


def extract_bullet_items(text: str) -> List[str]:
    """提取Markdown列表项"""
    items = []
    for line in text.split('\n'):
        line = line.strip()
        # 匹配 - 、* 、数字. 开头的列表项
        if re.match(r'^[-*]\s+', line):
            items.append(re.sub(r'^[-*]\s+', '', line))
        elif re.match(r'^\d+[.)]\s+', line):
            items.append(re.sub(r'^\d+[.)]\s+', '', line))
    return items


def extract_from_pattern(text: str, pattern: str) -> List[str]:
    """使用正则表达式从文本中提取匹配项"""
    matches = re.findall(pattern, text, re.IGNORECASE)
    return [m.strip() for m in matches if m.strip()]


# =============================================================================
# 简历解析器
# =============================================================================

class ResumeParser:
    """简历文本解析器 - 从非结构化文本中提取结构化简历信息"""

    # 常见章节标题映射（标准化）
    SECTION_ALIASES = {
        "基本信息": ["基本信息", "个人资料", "个人简介", "基本资料", "个人信息", "profile"],
        "联系方式": ["联系方式", "联系信息", "联系方法", "contact"],
        "教育经历": ["教育经历", "教育背景", "学历", "education", "学术背景"],
        "工作经历": ["工作经历", "工作背景", "职业经历", "工作经验", "工作经历", "employment",
                    "职业经验", "工作"],
        "项目经历": ["项目经历", "项目经验", "项目", "projects", "项目背景"],
        "专业技能": ["专业技能", "技术能力", "技能", "skills", "技术栈", "技术清单",
                    "核心技能", "专业能力", "技术能力"],
        "证书": ["证书", "认证", "资质", "certifications", "资格认证", "资格证书"],
        "语言能力": ["语言能力", "语言", "languages", "外语能力"],
        "自我评价": ["自我评价", "个人总结", "自我介绍", "summary", "关于我",
                    "个人概述", "个人简介", "职业概述"],
    }

    # 学历关键词
    DEGREE_KEYWORDS = {
        "博士": ["博士", "phd", "doctor", "博士研究生"],
        "硕士": ["硕士", "master", "硕士研究生", "m.s.", "m.sc"],
        "本科": ["本科", "学士", "bachelor", "b.s.", "b.sc", "大学", "学士"],
        "大专": ["大专", "专科", "associate", "高职", "专科"],
        "高中": ["高中", "high school"],
    }

    def __init__(self):
        self.skill_aliases = {}
        # 加载默认技能别名
        self._load_default_aliases()

    def _load_default_aliases(self):
        """加载默认的技能别名映射"""
        default_aliases = {
            "ml": "machine learning", "dl": "deep learning", "ai": "artificial intelligence",
            "k8s": "kubernetes", "golang": "go", "js": "javascript", "ts": "typescript",
            "py": "python", "rb": "ruby", "db": "database", "os": "operating system",
            "ci/cd": "continuous integration", "devops": "development operations",
            "spa": "single page application", "orm": "object relational mapping",
            "rest": "restful api", "sql": "structured query language",
            "nosql": "non-relational database", "aws": "amazon web services",
            "gcp": "google cloud platform", "azure": "microsoft azure",
            "nginx": "web server", "vue": "vue.js", "react": "react.js",
        }
        self.skill_aliases.update(default_aliases)

    def add_skill_alias(self, alias: str, canonical: str):
        """添加自定义技能别名"""
        self.skill_aliases[alias.lower()] = canonical.lower()

    def parse(self, text: str) -> Dict[str, Any]:
        """
        解析简历文本，返回结构化数据

        参数:
            text: 简历文本（Markdown或纯文本）

        返回:
            包含以下键的字典:
            - basic_info: 基本信息（姓名、电话、邮箱等）
            - education: 教育经历列表
            - work_experience: 工作经历列表
            - skills: 技能列表
            - projects: 项目经历列表
            - certifications: 证书列表
            - languages: 语言能力列表
            - summary: 自我评价
        """
        text = normalize_text(text)
        sections = extract_sections(text)
        result = {
            "basic_info": self._parse_basic_info(text, sections),
            "education": self._parse_education(text, sections),
            "work_experience": self._parse_work_experience(text, sections),
            "skills": self._parse_skills(text, sections),
            "projects": self._parse_projects(text, sections),
            "certifications": self._parse_certifications(text, sections),
            "languages": self._parse_languages(text, sections),
            "summary": self._parse_summary(text, sections),
        }
        return result

    def _resolve_section(self, sections: Dict[str, str], target: str) -> str:
        """根据别名解析章节内容"""
        aliases = self.SECTION_ALIASES.get(target, [target])
        for alias in aliases:
            for section_title, section_content in sections.items():
                if alias.lower() in section_title.lower():
                    return section_content
        # 如果找不到对应章节，尝试在全部文本中搜索
        return ""

    def _parse_basic_info(self, full_text: str, sections: Dict[str, str]) -> Dict[str, str]:
        """解析基本信息"""
        info = {}
        content = self._resolve_section(sections, "基本信息")

        # 提取姓名（通常在第一行或标题行）
        first_line = full_text.split('\n')[0].strip()
        # 去除Markdown标题符号
        name_match = re.search(r'^(?:#*\s*)?([^\s\-|,，]{2,10})', first_line)
        if name_match:
            info["name"] = name_match.group(1).strip()

        # 提取手机号
        phone_patterns = [
            r'1[3-9]\d{9}',
            r'(?:\+86\s*)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}',
            r'电话[：:\s]*(\d[\d\-]+)',
        ]
        for pattern in phone_patterns:
            match = re.search(pattern, full_text)
            if match:
                info["phone"] = re.sub(r'[\s\-]', '', match.group(0)[-11:])
                break

        # 提取邮箱
        email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.]+', full_text)
        if email_match:
            info["email"] = email_match.group(0)

        # 提取工作年限
        years_match = re.search(r'(?:工作年限|经验)[：:\s]*(\d+)\s*年', full_text)
        if years_match:
            info["years_of_experience"] = int(years_match.group(1))
        else:
            # 尝试从工作经历推算
            info["years_of_experience"] = self._estimate_experience_years(sections)

        # 提取所在地
        location_match = re.search(r'(?:所在[地城市]|城市|location)[：:\s]*([^\n,，]+)', full_text)
        if location_match:
            info["location"] = location_match.group(1).strip()

        return info

    def _estimate_experience_years(self, sections: Dict[str, str]) -> int:
        """从工作经历章节估算工作年限"""
        work_content = self._resolve_section(sections, "工作经历")
        if not work_content:
            return 0
        # 尝试提取年份范围
        year_ranges = re.findall(r'(\d{4})\s*[-–—~至]\s*(\d{4}|至今|现在|present)', work_content)
        if year_ranges:
            earliest = min(int(r[0]) for r in year_ranges)
            return max(0, 2026 - earliest)
        return 0

    def _parse_education(self, full_text: str, sections: Dict[str, str]) -> List[Dict[str, str]]:
        """解析教育经历"""
        content = self._resolve_section(sections, "教育经历")
        if not content:
            return []

        entries = []
        # 按常见的分隔模式切分教育条目（年份或大学名开头）
        edu_blocks = re.split(r'\n(?=\d{4}|(?:?!-).{2,20}(?:大学|学院|学校|University|Institute))', content)

        for block in edu_blocks:
            if not block.strip():
                continue
            entry = {}
            # 提取学校
            school_match = re.search(r'([\u4e00-\u9fa5]{2,15}(?:大学|学院|学校)|[A-Za-z\s]+University|[A-Za-z\s]+Institute)', block)
            if school_match:
                entry["school"] = school_match.group(1).strip()

            # 提取学历
            for degree_name, keywords in self.DEGREE_KEYWORDS.items():
                for kw in keywords:
                    if kw.lower() in block.lower():
                        entry["degree"] = degree_name
                        break
                if "degree" in entry:
                    break

            # 提取专业
            major_match = re.search(r'(?:专业|major)[：:\s]*([^\n,，;；]+)', block)
            if major_match:
                entry["major"] = major_match.group(1).strip()
            else:
                # 尝试从"XX专业"模式提取
                major_match2 = re.search(r'([\u4e00-\u9fa5]{2,20}(?:专业|方向))', block)
                if major_match2:
                    entry["major"] = major_match2.group(1).strip()

            # 提取时间段
            period_match = re.search(r'(\d{4})\s*[-–—~至]\s*(\d{4}|至今|现在)', block)
            if period_match:
                entry["period"] = f"{period_match.group(1)}-{period_match.group(2)}"

            if entry:
                entries.append(entry)

        return entries

    def _parse_work_experience(self, full_text: str, sections: Dict[str, str]) -> List[Dict[str, Any]]:
        """解析工作经历"""
        content = self._resolve_section(sections, "工作经历")
        if not content:
            return []

        entries = []
        # 按公司/组织名开头切分
        work_blocks = re.split(r'\n(?=[^\n#\-*]{2,30}(?:公司|集团|科技|技术|有限| Corp| Inc| Ltd))', content)

        for block in work_blocks:
            if not block.strip() or len(block.strip()) < 20:
                continue
            entry = {}

            # 提取公司名
            company_match = re.search(r'([\u4e00-\u9fa5A-Za-z0-9]{2,30}(?:公司|集团|科技|技术|有限| Corp| Inc| Ltd\.?| LLC))', block)
            if company_match:
                entry["company"] = company_match.group(1).strip()

            # 提取职位
            title_patterns = [
                r'(?:职位|岗位|title)[：:\s]*([^\n,，;；]+)',
                r'(?:担任|任职|角色)[：:\s]*([^\n]+)',
                r'([\u4e00-\u9fa5A-Za-z]{2,20}(?:工程师|经理|总监|设计师|分析师|专员|主管|架构师|顾问|专家|主任))',
            ]
            for pattern in title_patterns:
                title_match = re.search(pattern, block)
                if title_match:
                    entry["title"] = title_match.group(1).strip()
                    break

            # 提取时间段
            period_match = re.search(r'(\d{4})[./]?\d{0,2}\s*[-–—~至]\s*(\d{4}[./]?\d{0,2}|至今|现在|present)', block)
            if period_match:
                entry["period"] = f"{period_match.group(1)}-{period_match.group(2)}"

            # 提取工作描述（列表项）
            description_items = extract_bullet_items(block)
            entry["description"] = description_items if description_items else block.strip()[:200]

            if entry:
                entries.append(entry)

        return entries

    def _parse_skills(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析技能清单"""
        content = self._resolve_section(sections, "专业技能")
        if not content:
            # 尝试从全文提取技能关键词
            content = full_text

        skills = []
        # 从列表项中提取
        bullet_items = extract_bullet_items(content)
        for item in bullet_items:
            # 提取冒号后的技能列表
            if '：' in item or ':' in item:
                skill_part = re.split(r'[：:]', item)[-1].strip()
                # 按逗号/斜杠分割
                skill_parts = re.split(r'[,，、/|]', skill_part)
                skills.extend([s.strip() for s in skill_parts if s.strip()])

        # 从常见模式提取
        # "编程语言：Python, Java, Go" 类模式
        colon_pattern = re.findall(r'(?:编程|框架|数据库|中间件|工具|云[服务平台]|DevOps|操作系统|语言)[：:]\s*(.+?)(?:\n|$)', content)
        for match in colon_pattern:
            parts = re.split(r'[,，、/|]', match)
            skills.extend([s.strip() for s in parts if s.strip()])

        # 括号中的技能（如 "熟悉 Spring Boot (2.x)"）
        paren_skills = re.findall(r'([A-Za-z][\w#+.]*|[A-Z][A-Za-z]+)', content)
        skills.extend(paren_skills)

        # 去重并标准化
        seen = set()
        normalized_skills = []
        for skill in skills:
            s_lower = skill.lower().strip()
            if not s_lower or len(s_lower) < 2:
                continue
            # 检查别名
            canonical = self.skill_aliases.get(s_lower, s_lower)
            if canonical.lower() not in seen:
                seen.add(canonical.lower())
                normalized_skills.append(canonical)
        return normalized_skills

    def _parse_projects(self, full_text: str, sections: Dict[str, str]) -> List[Dict[str, Any]]:
        """解析项目经历"""
        content = self._resolve_section(sections, "项目经历")
        if not content:
            return []

        entries = []
        # 按项目名切分（通常是加粗或标题行）
        project_blocks = re.split(r'\n(?=\*{0,2}[^\n*]{3,50}\*{0,2}\s*$)', content)

        for block in project_blocks:
            if not block.strip() or len(block.strip()) < 15:
                continue
            entry = {}

            # 提取项目名
            name_match = re.search(r'^[*#]?\s*(.+?)\s*[*#]?\s*$', block.split('\n')[0])
            if name_match:
                entry["name"] = name_match.group(1).strip()

            # 提取角色
            role_match = re.search(r'(?:角色|担任|职责|role)[：:\s]*([^\n,，;；]+)', block)
            if role_match:
                entry["role"] = role_match.group(1).strip()

            # 提取描述
            description_items = extract_bullet_items(block)
            entry["description"] = description_items if description_items else []

            # 提取技术栈
            tech_match = re.search(r'(?:技术栈|技术[方案架构]|tech stack)[：:\s]*([^\n]+)', block, re.IGNORECASE)
            if tech_match:
                entry["tech_stack"] = [t.strip() for t in re.split(r'[,，、/|]', tech_match.group(1)) if t.strip()]

            if entry.get("name"):
                entries.append(entry)

        return entries

    def _parse_certifications(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析证书/认证"""
        content = self._resolve_section(sections, "证书")
        if not content:
            return []
        items = extract_bullet_items(content)
        if not items:
            items = re.findall(r'[\u4e00-\u9fa5A-Za-z0-9]{4,50}(?:证书|认证|资格|工程师|Certified)', full_text)
        return items

    def _parse_languages(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析语言能力"""
        content = self._resolve_section(sections, "语言能力")
        if not content:
            return []
        # 提取语言和熟练程度
        lang_pattern = re.findall(r'(?:英语|中文|日语|韩语|法语|德语|西班牙语|English|Chinese|Japanese|Korean|French|German|Spanish)[^\n]*', content)
        return [l.strip() for l in lang_pattern if l.strip()]

    def _parse_summary(self, full_text: str, sections: Dict[str, str]) -> str:
        """解析自我评价/个人总结"""
        content = self._resolve_section(sections, "自我评价")
        if content:
            return content.strip()[:500]
        return ""


# =============================================================================
# JD 解析器
# =============================================================================

class JDParser:
    """岗位描述（JD）解析器 - 从JD文本中提取结构化岗位要求"""

    # 经验年限关键词
    EXPERIENCE_PATTERNS = [
        r'(\d+)\s*[-~至]\s*(\d+)\s*年(?:以上|左右)?(?:工作经验|经验)?',
        r'(?:至少|最低|minimum)\s*(\d+)\s*年(?:工作经验|经验)?',
        r'(\d+)\s*年(?:以上|及以上)?(?:工作经验|经验|开发经验)',
        r'(\d+)\s*\+\s*(?:年|years)',
    ]

    def parse(self, text: str) -> Dict[str, Any]:
        """
        解析JD文本，返回结构化数据

        返回:
            - position: 岗位基本信息（标题、部门、地点等）
            - required_skills: 必须技能列表
            - preferred_skills: 加分技能列表
            - experience: 经验要求
            - education: 学历要求
            - responsibilities: 岗位职责列表
            - soft_skills: 软实力要求
            - industry_domain: 行业领域
        """
        text = normalize_text(text)
        sections = extract_sections(text)

        return {
            "position": self._parse_position(text, sections),
            "required_skills": self._parse_required_skills(text, sections),
            "preferred_skills": self._parse_preferred_skills(text, sections),
            "experience": self._parse_experience(text, sections),
            "education": self._parse_education(text, sections),
            "responsibilities": self._parse_responsibilities(text, sections),
            "soft_skills": self._parse_soft_skills(text, sections),
            "industry_domain": self._parse_industry(text, sections),
        }

    def _parse_position(self, full_text: str, sections: Dict[str, str]) -> Dict[str, str]:
        """解析岗位基本信息"""
        info = {}
        first_line = full_text.split('\n')[0].strip()
        title_match = re.search(r'^#*\s*(.+)', first_line)
        if title_match:
            info["title"] = title_match.group(1).strip()

        # 提取部门
        dept_match = re.search(r'(?:部门|department|所属)[：:\s]*([^\n,，]+)', full_text)
        if dept_match:
            info["department"] = dept_match.group(1).strip()

        # 提取工作地点
        loc_match = re.search(r'(?:工作地点|地点|城市|location)[：:\s]*([^\n,，]+)', full_text)
        if loc_match:
            info["location"] = loc_match.group(1).strip()

        # 提取工作类型
        type_match = re.search(r'(?:工作类型|类型|用工形式)[：:\s]*([^\n,，]+)', full_text)
        if type_match:
            info["type"] = type_match.group(1).strip()

        # 提取薪资范围
        salary_match = re.search(r'(\d+[kKwW万]?[-~至]\d+[kKwW万]?)(?:/月|/年)?(?:薪资|薪酬|待遇)?', full_text)
        if salary_match:
            info["salary_range"] = salary_match.group(1).strip()

        return info

    def _parse_required_skills(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析必须技能"""
        skills = []
        # 优先从"岗位要求"章节提取
        requirement_section = ""
        for title, content in sections.items():
            if any(kw in title.lower() for kw in ["要求", "任职", "qualification", "requirement"]):
                requirement_section = content
                break

        if not requirement_section:
            requirement_section = full_text

        # 提取"精通/熟练/掌握"后面跟的技能
        skill_patterns = [
            r'精通\s+([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9+#.]+)',
            r'熟练(?:掌握|使用|运用)?\s+([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9+#.]+)',
            r'掌握\s+([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9+#.]+)',
            r'熟悉\s+([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9+#.]+)',
            r'(?:具备|具有|拥有)\s+([\u4e00-\u9fa5A-Za-z][\u4e00-\u9fa5A-Za-z0-9+\s]*?能力)',
        ]
        for pattern in skill_patterns:
            matches = re.findall(pattern, requirement_section)
            skills.extend([m.strip() for m in matches])

        # 从列表项提取
        bullet_items = extract_bullet_items(requirement_section)
        for item in bullet_items:
            for pattern in skill_patterns:
                match = re.search(pattern, item)
                if match:
                    skill = match.group(1).strip()
                    if skill not in skills:
                        skills.append(skill)

        return skills

    def _parse_preferred_skills(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析加分/优先技能"""
        skills = []
        # 查找包含"优先"/"加分"/"加分项"的内容
        pref_pattern = re.findall(r'(?:优先|加分|preferred|bonus|plus)[：:\s]*([^\n]+)', full_text)
        for match in pref_pattern:
            parts = re.split(r'[,，、/|;；]', match)
            skills.extend([p.strip() for p in parts if p.strip() and len(p.strip()) > 1])
        return skills

    def _parse_experience(self, full_text: str, sections: Dict[str, str]) -> Dict[str, Any]:
        """解析经验要求"""
        exp_info = {}
        for pattern in self.EXPERIENCE_PATTERNS:
            matches = re.findall(pattern, full_text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    exp_info["min_years"] = int(match[0])
                    exp_info["max_years"] = int(match[1]) if match[1].isdigit() else None
                else:
                    exp_info["min_years"] = int(match)
                break
            if exp_info:
                break
        return exp_info

    def _parse_education(self, full_text: str, sections: Dict[str, str]) -> Dict[str, str]:
        """解析学历要求"""
        edu_info = {}
        degree_patterns = [
            (r'本科(?:及以上)?', "本科"),
            (r'硕士(?:及以上|以上)?', "硕士"),
            (r'博士(?:及以上|以上)?', "博士"),
            (r'大专(?:及以上|以上)?', "大专"),
            (r'学士(?:学位)?(?:及以上)?', "本科"),
            (r'全日制(?:本科|硕士|博士)', None),  # 特殊处理
        ]
        for pattern, degree in degree_patterns:
            match = re.search(pattern, full_text)
            if match:
                if degree:
                    edu_info["min_degree"] = degree
                else:
                    # 从匹配中提取学历
                    m = re.search(r'(本科|硕士|博士|大专)', match.group(0))
                    if m:
                        edu_info["min_degree"] = m.group(1)
                break

        # 提取专业要求
        major_match = re.search(r'(?:专业|major)[：:\s]*([^\n,，]+)', full_text)
        if major_match:
            edu_info["preferred_major"] = major_match.group(1).strip()

        return edu_info

    def _parse_responsibilities(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析岗位职责"""
        for title, content in sections.items():
            if any(kw in title.lower() for kw in ["职责", "工作内容", "responsibility", "duty"]):
                items = extract_bullet_items(content)
                if items:
                    return items
                # 如果没有列表项，按句号分割
                sentences = re.split(r'[。！？\n]', content)
                return [s.strip() for s in sentences if len(s.strip()) > 10]
        return []

    def _parse_soft_skills(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析软实力要求"""
        soft_keywords = [
            "沟通能力", "团队合作", "团队协作", "领导力", "管理能力",
            "学习能力", "抗压能力", "问题解决", "创新思维", "责任心",
            "自驱力", "执行力", "跨部门", "协调能力", "表达能力",
            "逻辑思维", "分析能力", "项目管理", "时间管理",
            "communication", "leadership", "teamwork", "problem-solving",
        ]
        found = []
        for kw in soft_keywords:
            if kw in full_text:
                found.append(kw)
        return found

    def _parse_industry(self, full_text: str, sections: Dict[str, str]) -> List[str]:
        """解析行业领域"""
        industries = []
        industry_keywords = [
            "互联网", "金融", "教育", "医疗", "电商", "游戏", "AI", "人工智能",
            "SaaS", "云计算", "大数据", "物联网", "区块链", "新能源", "制造业",
            "零售", "物流", "咨询", "媒体", "社交", "出行", "房产",
            "fintech", "healthcare", "e-commerce", "gaming", "AI",
        ]
        for ind in industry_keywords:
            if ind.lower() in full_text.lower():
                industries.append(ind)
        return list(set(industries))


# =============================================================================
# 匹配引擎
# =============================================================================

class ResumeJDMatcher:
    """
    简历-JD匹配引擎
    执行多维度匹配分析并生成结构化报告
    """

    # 默认权重配置
    DEFAULT_WEIGHTS = {
        "skill": 0.30,
        "experience": 0.25,
        "education": 0.15,
        "project": 0.20,
        "soft_skill": 0.10,
    }

    # 岗位类型预设权重
    PRESET_WEIGHTS = {
        "tech": {"skill": 0.40, "experience": 0.25, "education": 0.10, "project": 0.20, "soft_skill": 0.05},
        "management": {"skill": 0.15, "experience": 0.30, "education": 0.10, "project": 0.20, "soft_skill": 0.25},
        "design": {"skill": 0.30, "experience": 0.15, "education": 0.20, "project": 0.30, "soft_skill": 0.05},
        "sales": {"skill": 0.10, "experience": 0.30, "education": 0.05, "project": 0.15, "soft_skill": 0.40},
        "general": {"skill": 0.25, "experience": 0.25, "education": 0.15, "project": 0.20, "soft_skill": 0.15},
    }

    # 技能近似匹配表（同一技术栈的不同工具/框架）
    SKILL_SIMILARITY = {
        ("django", "flask"): 0.7, ("django", "fastapi"): 0.7,
        ("spring boot", "spring cloud"): 0.7, ("spring boot", "spring framework"): 0.8,
        ("mysql", "postgresql"): 0.8, ("mysql", "mariadb"): 0.9,
        ("redis", "memcached"): 0.7, ("kafka", "rabbitmq"): 0.6,
        ("react", "vue"): 0.5, ("angular", "react"): 0.5, ("angular", "vue"): 0.5,
        ("aws", "gcp"): 0.7, ("aws", "azure"): 0.7,
        ("jenkins", "gitlab ci"): 0.6, ("jenkins", "github actions"): 0.6,
        ("tensorflow", "pytorch"): 0.7, ("tensorflow", "keras"): 0.8,
    }

    # 学历达标分映射表
    DEGREE_SCORE_MATRIX = {
        ("博士", "博士"): 100, ("博士", "硕士"): 70, ("博士", "本科"): 40, ("博士", "大专"): 20,
        ("硕士", "博士"): 100, ("硕士", "硕士"): 100, ("硕士", "本科"): 60, ("硕士", "大专"): 30,
        ("本科", "博士"): 100, ("本科", "硕士"): 100, ("本科", "本科"): 100, ("本科", "大专"): 50,
    }

    def __init__(self, weights: Dict[str, float] = None, preset: str = None):
        """
        初始化匹配引擎

        参数:
            weights: 自定义维度权重 {"skill": 0.4, "experience": 0.25, ...}
            preset: 预设权重方案 ("tech", "management", "design", "sales", "general")
        """
        if preset and preset in self.PRESET_WEIGHTS:
            self.weights = self.PRESET_WEIGHTS[preset]
        elif weights:
            self.weights = weights
        else:
            self.weights = self.DEFAULT_WEIGHTS.copy()

        self.resume_parser = ResumeParser()
        self.jd_parser = JDParser()

        # 验证权重和为1.0
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            # 归一化
            self.weights = {k: v / total for k, v in self.weights.items()}

    def add_skill_alias(self, alias: str, canonical: str):
        """添加技能别名映射"""
        self.resume_parser.add_skill_alias(alias, canonical)

    def normalize_text(self, text: str) -> str:
        """文本标准化"""
        return normalize_text(text)

    def parse_resume(self, resume_text: str) -> Dict[str, Any]:
        """解析简历"""
        return self.resume_parser.parse(resume_text)

    def parse_jd(self, jd_text: str) -> Dict[str, Any]:
        """解析JD"""
        return self.jd_parser.parse(jd_text)

    def match(self, resume_text: str, jd_text: str) -> Dict[str, Any]:
        """
        执行完整的匹配分析（一站式接口）

        参数:
            resume_text: 简历文本
            jd_text: JD文本

        返回:
            完整的匹配结果字典
        """
        resume_data = self.parse_resume(resume_text)
        jd_data = self.parse_jd(jd_text)
        return self.compute_match(resume_data, jd_data)

    def compute_match(self, resume_data: Dict, jd_data: Dict) -> Dict[str, Any]:
        """
        基于已解析的数据执行多维度匹配计算

        参数:
            resume_data: 解析后的简历数据
            jd_data: 解析后的JD数据

        返回:
            包含overall_score、dimensions、gaps、highlights、risk_areas的结果字典
        """
        # 各维度评分
        skill_result = self._match_skills(resume_data.get("skills", []), 
                                          jd_data.get("required_skills", []),
                                          jd_data.get("preferred_skills", []))
        experience_result = self._match_experience(resume_data, jd_data)
        education_result = self._match_education(resume_data, jd_data)
        project_result = self._match_projects(resume_data, jd_data)
        soft_skill_result = self._match_soft_skills(resume_data, jd_data)

        # 计算加权总分
        scores = {
            "skill_match": skill_result["score"],
            "experience_match": experience_result["score"],
            "education_match": education_result["score"],
            "project_match": project_result["score"],
            "soft_skill_match": soft_skill_result["score"],
        }

        overall = 0.0
        weight_map = {
            "skill_match": "skill",
            "experience_match": "experience",
            "education_match": "education",
            "project_match": "project",
            "soft_skill_match": "soft_skill",
        }
        for dim, score in scores.items():
            w_key = weight_map[dim]
            overall += score * self.weights.get(w_key, 0)

        # 生成差距列表
        gaps = self._generate_gaps(skill_result, experience_result, education_result,
                                    project_result, soft_skill_result, jd_data)

        # 生成亮点
        highlights = self._generate_highlights(resume_data, jd_data, scores)

        # 生成风险区域
        risk_areas = self._generate_risks(scores, gaps)

        # 亮点加分和风险扣分
        highlight_bonus = min(5.0, len(highlights) * 1.0)
        risk_penalty = min(10.0, sum(2.0 for g in gaps if g["severity"] == "high"))
        overall = max(0, min(100, overall + highlight_bonus - risk_penalty))

        return {
            "overall_score": round(overall, 1),
            "dimensions": {
                "skill_match": skill_result,
                "experience_match": experience_result,
                "education_match": education_result,
                "project_match": project_result,
                "soft_skill_match": soft_skill_result,
            },
            "gaps": gaps,
            "highlights": highlights,
            "risk_areas": risk_areas,
            "weights": self.weights,
        }

    def _match_skills(self, resume_skills: List[str], required_skills: List[str],
                      preferred_skills: List[str]) -> Dict[str, Any]:
        """技能维度匹配"""
        matched = []
        missing = []
        extra = []
        partial_matched = []

        resume_lower = {s.lower(): s for s in resume_skills}

        for req_skill in required_skills:
            req_lower = req_skill.lower()
            if req_lower in resume_lower:
                matched.append(req_skill)
            else:
                # 检查近似匹配
                found_similar = False
                for r_lower, r_original in resume_lower.items():
                    sim = self._skill_similarity(req_lower, r_lower)
                    if sim >= 0.7:
                        partial_matched.append({"required": req_skill, "resume": r_original, "similarity": sim})
                        found_similar = True
                        break
                if not found_similar:
                    missing.append(req_skill)

        # 计算技能匹配分
        total_required = len(required_skills)
        if total_required == 0:
            score = 100  # 没有技能要求则满分
        else:
            effective_match = len(matched) + sum(p["similarity"] for p in partial_matched)
            score = min(100, (effective_match / total_required) * 100)

        # 简历中有但JD未要求的技能
        for s in resume_skills:
            s_lower = s.lower()
            if not any(s_lower == r.lower() or self._skill_similarity(s_lower, r.lower()) >= 0.7
                       for r in required_skills):
                extra.append(s)

        return {
            "score": round(score),
            "matched": matched,
            "partial_matched": partial_matched,
            "missing": missing,
            "extra": extra,
        }

    def _skill_similarity(self, skill_a: str, skill_b: str) -> float:
        """计算两个技能的相似度"""
        a, b = skill_a.lower(), skill_b.lower()
        if a == b:
            return 1.0

        # 查表
        for (s1, s2), sim in self.SKILL_SIMILARITY.items():
            if (a == s1 and b == s2) or (a == s2 and b == s1):
                return sim

        # 包含关系
        if a in b or b in a:
            return 0.7

        # 编辑距离相似度
        if len(set(a) & set(b)) / max(len(set(a)), len(set(b)), 1) > 0.6:
            return 0.5

        return 0.0

    def _match_experience(self, resume_data: Dict, jd_data: Dict) -> Dict[str, Any]:
        """经验维度匹配"""
        resume_years = resume_data.get("basic_info", {}).get("years_of_experience", 0)
        jd_exp = jd_data.get("experience", {})
        min_years = jd_exp.get("min_years", 0)
        max_years = jd_exp.get("max_years")

        analysis_parts = []

        if min_years == 0:
            # JD没有明确经验要求
            score = 100
            analysis_parts.append("JD未明确经验年限要求")
        elif resume_years >= min_years:
            # 满足最低要求
            base_score = min(100, (resume_years / min_years) * 100) if min_years > 0 else 100
            if max_years and resume_years > max_years:
                # 超出上限，适度扣分（经验过于资深可能不匹配）
                over_ratio = (resume_years - max_years) / max_years
                penalty = min(20, over_ratio * 20)
                base_score -= penalty
                analysis_parts.append(f"工作年限{resume_years}年，超出JD上限{max_years}年，可能资历偏高")
            score = base_score
            analysis_parts.append(f"满足最低{min_years}年经验要求（实际{resume_years}年）")
        else:
            gap = min_years - resume_years
            score = max(0, (resume_years / min_years) * 60)
            analysis_parts.append(f"缺少{gap}年经验（要求{min_years}年，实际{resume_years}年）")

        # 评估工作领域相关度
        resume_companies = [w.get("company", "") for w in resume_data.get("work_experience", [])]
        jd_industry = jd_data.get("industry_domain", [])
        if resume_companies and jd_industry:
            analysis_parts.append(f"工作经历行业: {', '.join(resume_companies[:3])}")
            analysis_parts.append(f"目标行业: {', '.join(jd_industry[:3])}")

        return {
            "score": round(min(100, max(0, score))),
            "analysis": "；".join(analysis_parts),
            "resume_years": resume_years,
            "jd_min_years": min_years,
            "jd_max_years": max_years,
        }

    def _match_education(self, resume_data: Dict, jd_data: Dict) -> Dict[str, Any]:
        """教育背景维度匹配"""
        education_list = resume_data.get("education", [])
        jd_edu = jd_data.get("education", {})
        jd_min_degree = jd_edu.get("min_degree", "")

        if not jd_min_degree or not education_list:
            score = 85  # 无明确要求时给中等偏高分数
            analysis = "学历要求不明确或简历无教育信息" if not education_list else "JD未明确学历要求"
            return {"score": score, "analysis": analysis}

        # 取最高学历
        degree_rank = {"博士": 4, "硕士": 3, "本科": 2, "大专": 1}
        max_resume_degree = "大专"
        for edu in education_list:
            degree = edu.get("degree", "")
            if degree_rank.get(degree, 0) > degree_rank.get(max_resume_degree, 0):
                max_resume_degree = degree

        # 查表获取学历达标分
        score_key = (jd_min_degree, max_resume_degree)
        degree_score = self.DEGREE_SCORE_MATRIX.get(score_key, 50)

        # 专业匹配加分
        jd_major = jd_edu.get("preferred_major", "")
        major_match_score = 80  # 默认专业相关度
        if jd_major and education_list:
            for edu in education_list:
                major = edu.get("major", "")
                if major and any(kw in major for kw in jd_major.split(',')):
                    major_match_score = 100
                    break
                elif major:
                    major_match_score = 60

        score = degree_score * 0.6 + major_match_score * 0.4
        analysis = f"最高学历{max_resume_degree}（要求{jd_min_degree}，达标分{degree_score}）；专业相关度{major_match_score}"

        return {"score": round(score), "analysis": analysis}

    def _match_projects(self, resume_data: Dict, jd_data: Dict) -> Dict[str, Any]:
        """项目经历维度匹配"""
        projects = resume_data.get("projects", [])
        responsibilities = jd_data.get("responsibilities", [])
        jd_skills = jd_data.get("required_skills", [])

        if not projects:
            return {"score": 40, "analysis": "简历中无项目经历信息"}

        # 评估项目与岗位职责的匹配度
        matched_aspects = []
        missing_aspects = []

        project_descriptions = " ".join(
            [" ".join(p.get("description", [])) for p in projects]
        )

        # 检查JD职责关键词在项目中的出现
        for resp in responsibilities:
            # 提取职责中的关键动词+名词
            keywords = re.findall(r'[\u4e00-\u9fa5]{2,10}', resp)
            matched_count = sum(1 for kw in keywords if kw in project_descriptions)
            if matched_count > 0:
                matched_aspects.append(resp[:20])
            elif len(keywords) > 2:
                missing_aspects.append(resp[:20])

        # 评估项目技术栈与JD要求技能的覆盖度
        project_techs = set()
        for p in projects:
            project_techs.update(p.get("tech_stack", []))
        tech_coverage = 0
        if jd_skills and project_techs:
            covered = sum(1 for s in jd_skills if any(s.lower() in t.lower() for t in project_techs))
            tech_coverage = (covered / len(jd_skills)) * 100

        # 综合评分
        base_score = min(100, len(matched_aspects) / max(len(responsibilities), 1) * 80 + 20)
        score = base_score * 0.6 + tech_coverage * 0.4

        analysis_parts = [f"共{len(projects)}个项目经历"]
        if matched_aspects:
            analysis_parts.append(f"匹配JD职责{len(matched_aspects)}项")
        if missing_aspects:
            analysis_parts.append(f"未覆盖职责{len(missing_aspects)}项")
        if project_techs:
            analysis_parts.append(f"项目技术栈覆盖JD技能{tech_coverage:.0f}%")

        return {
            "score": round(score),
            "analysis": "；".join(analysis_parts),
            "project_count": len(projects),
            "matched_aspects": matched_aspects[:5],
            "missing_aspects": missing_aspects[:5],
        }

    def _match_soft_skills(self, resume_data: Dict, jd_data: Dict) -> Dict[str, Any]:
        """软实力维度匹配"""
        jd_soft = jd_data.get("soft_skills", [])
        if not jd_soft:
            return {"score": 80, "matched": [], "missing": []}

        # 从简历全文搜索软实力关键词
        resume_full_text = ""
        for exp in resume_data.get("work_experience", []):
            if isinstance(exp.get("description"), list):
                resume_full_text += " ".join(exp["description"])
            else:
                resume_full_text += str(exp.get("description", ""))
        resume_full_text += resume_data.get("summary", "")
        for proj in resume_data.get("projects", []):
            if isinstance(proj.get("description"), list):
                resume_full_text += " ".join(proj["description"])

        matched = []
        missing = []
        for skill in jd_soft:
            if skill in resume_full_text or skill.lower() in resume_full_text.lower():
                matched.append(skill)
            else:
                missing.append(skill)

        score = (len(matched) / len(jd_soft) * 100) if jd_soft else 80
        return {"score": round(score), "matched": matched, "missing": missing}

    def _generate_gaps(self, skill_result, exp_result, edu_result,
                      project_result, soft_result, jd_data) -> List[Dict]:
        """生成差距列表"""
        gaps = []

        # 技能差距
        for skill in skill_result.get("missing", []):
            gaps.append({
                "item": skill,
                "severity": "high",
                "category": "技能",
                "suggestion": f"建议在简历中补充{skill}相关的学习或项目经验，或考虑参加相关培训"
            })
        for partial in skill_result.get("partial_matched", []):
            gaps.append({
                "item": f"{partial['required']}（有近似经验：{partial['resume']}，相似度{partial['similarity']:.0%}）",
                "severity": "medium",
                "category": "技能",
                "suggestion": f"可将{partial['resume']}经验重新表述，突出与{partial['required']}的关联性"
            })

        # 经验差距
        if exp_result.get("jd_min_years", 0) > exp_result.get("resume_years", 0):
            gap_years = exp_result["jd_min_years"] - exp_result["resume_years"]
            gaps.append({
                "item": f"工作经验不足（缺{gap_years}年）",
                "severity": "high" if gap_years > 2 else "medium",
                "category": "经验",
                "suggestion": f"重点展示实习、项目、开源贡献等经历来弥补{gap_years}年的经验差距"
            })

        # 教育差距
        if edu_result.get("score", 100) < 60:
            gaps.append({
                "item": "学历未达JD要求",
                "severity": "medium",
                "category": "教育",
                "suggestion": "通过强调丰富的工作经验和项目成果来弥补学历差距"
            })

        # 项目差距
        for aspect in project_result.get("missing_aspects", []):
            gaps.append({
                "item": f"项目经历未覆盖：{aspect}",
                "severity": "medium",
                "category": "项目",
                "suggestion": f"补充与'{aspect}'相关的项目描述或工作经验"
            })

        # 软实力差距
        for skill in soft_result.get("missing", []):
            gaps.append({
                "item": f"软实力：{skill}",
                "severity": "low",
                "category": "软实力",
                "suggestion": f"在自我评价或工作经历中补充体现{skill}的具体事例"
            })

        # 按严重程度排序
        severity_order = {"high": 0, "medium": 1, "low": 2}
        gaps.sort(key=lambda x: severity_order.get(x["severity"], 3))

        return gaps

    def _generate_highlights(self, resume_data, jd_data, scores) -> List[str]:
        """生成匹配亮点"""
        highlights = []

        # 超额匹配的技能
        skill_result = scores.get("skill_match", {})
        if isinstance(skill_result, dict) and skill_result.get("extra"):
            extras = skill_result["extra"][:3]
            highlights.append(f"额外掌握的加分技能：{', '.join(extras)}")

        # 高分维度
        dim_names = {
            "skill_match": "技能匹配", "experience_match": "经验匹配",
            "education_match": "教育背景", "project_match": "项目经历",
            "soft_skill_match": "软实力"
        }
        for dim_key, dim_name in dim_names.items():
            val = scores.get(dim_key, {})
            s = val.get("score", 0) if isinstance(val, dict) else val
            if s >= 90:
                highlights.append(f"{dim_name}表现优异（{s}分）")

        # 项目经验丰富
        project_count = len(resume_data.get("projects", []))
        if project_count >= 3:
            highlights.append(f"项目经验丰富（{project_count}个项目）")

        return highlights

    def _generate_risks(self, scores, gaps) -> List[str]:
        """生成风险区域提示"""
        risks = []

        # 高严重度差距
        high_gaps = [g for g in gaps if g["severity"] == "high"]
        if len(high_gaps) >= 3:
            risks.append(f"存在{len(high_gaps)}项高严重度差距，整体匹配度偏低")

        # 经验风险
        exp_score = scores.get("experience_match", {})
        if isinstance(exp_score, dict) and exp_score.get("score", 100) < 50:
            risks.append("工作经验显著不足，可能影响简历筛选通过率")

        # 技能核心缺失
        skill_score = scores.get("skill_match", {})
        if isinstance(skill_score, dict) and skill_score.get("score", 100) < 50:
            risks.append("核心技能匹配度低，建议优先提升关键技能")

        # 教育短板
        edu_score = scores.get("education_match", {})
        if isinstance(edu_score, dict) and edu_score.get("score", 100) < 50:
            risks.append("学历不满足基本要求，这是硬性门槛风险")

        return risks

    def generate_report(self, match_result: Dict, resume_data: Dict = None,
                        jd_data: Dict = None, output_path: str = None,
                        template_path: str = None) -> str:
        """
        生成Markdown格式的匹配分析报告

        参数:
            match_result: compute_match的返回结果
            resume_data: 简历解析数据（可选，用于增强报告内容）
            jd_data: JD解析数据（可选，用于增强报告内容）
            output_path: 输出文件路径（可选）
            template_path: 报告模板路径（可选）

        返回:
            Markdown格式的报告字符串
        """
        report_lines = []
        result = match_result

        # 报告标题
        report_lines.append("# 简历-岗位匹配分析报告\n")
        report_lines.append(f"> 生成时间：{self._current_time()}\n")
        report_lines.append("> 匹配引擎版本：1.0.0\n\n")

        # 总体评分
        score = result["overall_score"]
        level = self._score_level(score)
        report_lines.append(f"## 匹配度总览\n")
        report_lines.append(f"### 总体评分：**{score}/100** （{level}）\n\n")

        # 评分等级图示
        bar_length = 20
        filled = int(score / 100 * bar_length)
        bar = "[" + "#" * filled + "-" * (bar_length - filled) + "]"
        report_lines.append(f"`{bar} {score}%`\n\n")

        # 各维度详情表格
        report_lines.append("### 各维度评分\n\n")
        report_lines.append("| 维度 | 评分 | 权重 | 加权分 | 状态 |")
        report_lines.append("|------|------|------|--------|------|")
        dim_config = [
            ("skill_match", "技能匹配", "skill"),
            ("experience_match", "经验匹配", "experience"),
            ("education_match", "教育背景", "education"),
            ("project_match", "项目经历", "project"),
            ("soft_skill_match", "软实力", "soft_skill"),
        ]
        for dim_key, dim_name, weight_key in dim_config:
            dim_data = result["dimensions"].get(dim_key, {})
            s = dim_data.get("score", 0)
            w = result["weights"].get(weight_key, 0)
            weighted = round(s * w, 2)
            status = "优秀" if s >= 85 else ("良好" if s >= 70 else ("一般" if s >= 50 else "不足"))
            report_lines.append(f"| {dim_name} | {s}/100 | {w:.0%} | {weighted} | {status} |")
        report_lines.append(f"| **总体匹配度** | | | **{score}** | **{level}** |\n\n")

        # 差距分析
        report_lines.append("## 差距分析\n")
        gaps = result.get("gaps", [])
        if not gaps:
            report_lines.append("> 未发现显著差距，简历与岗位匹配度较高。\n")
        else:
            severity_groups = {"high": [], "medium": [], "low": []}
            for g in gaps:
                severity_groups.get(g["severity"], severity_groups["low"]).append(g)

            for severity, label in [("high", "高严重度"), ("medium", "中严重度"), ("low", "低严重度")]:
                items = severity_groups[severity]
                if not items:
                    continue
                report_lines.append(f"### {label}\n")
                for i, g in enumerate(items, 1):
                    report_lines.append(f"{i}. **{g['item']}** [{g['category']}]")
                    report_lines.append(f"   - 建议：{g['suggestion']}\n")
        report_lines.append("")

        # 亮点
        report_lines.append("## 匹配亮点\n")
        for h in result.get("highlights", []):
            report_lines.append(f"- {h}")
        if not result.get("highlights"):
            report_lines.append("- 暂无突出亮点")
        report_lines.append("")

        # 风险提示
        report_lines.append("## 风险提示\n")
        for r in result.get("risk_areas", []):
            report_lines.append(f"- ⚠ {r}")
        if not result.get("risk_areas"):
            report_lines.append("- 未发现显著风险")
        report_lines.append("")

        # 各维度详细分析
        report_lines.append("## 各维度详细分析\n")
        for dim_key, dim_name, _ in dim_config:
            dim_data = result["dimensions"].get(dim_key, {})
            report_lines.append(f"### {dim_name}（{dim_data.get('score', 0)}分）\n")

            if dim_key == "skill_match":
                if dim_data.get("matched"):
                    report_lines.append("**已匹配技能：** " + ", ".join(dim_data["matched"]))
                if dim_data.get("missing"):
                    report_lines.append("**缺失技能：** " + ", ".join(dim_data["missing"]))
                if dim_data.get("extra"):
                    report_lines.append("**额外技能：** " + ", ".join(dim_data["extra"]))
                if dim_data.get("partial_matched"):
                    report_lines.append("**近似匹配：**")
                    for pm in dim_data["partial_matched"]:
                        report_lines.append(f"  - {pm['required']} ↔ {pm['resume']}（{pm['similarity']:.0%}）")

            elif "analysis" in dim_data:
                report_lines.append(dim_data["analysis"])

            report_lines.append("")

        # 行动计划
        report_lines.append("## 行动计划\n")
        report_lines.append("基于以上分析，建议按以下优先级采取行动：\n")
        high_gaps = [g for g in gaps if g["severity"] == "high"]
        medium_gaps = [g for g in gaps if g["severity"] == "medium"]
        low_gaps = [g for g in gaps if g["severity"] == "low"]

        if high_gaps:
            report_lines.append("### 立即行动（1-2周内）\n")
            for g in high_gaps:
                report_lines.append(f"- [ ] {g['item']}: {g['suggestion']}")
            report_lines.append("")
        if medium_gaps:
            report_lines.append("### 短期规划（1-3个月）\n")
            for g in medium_gaps[:5]:
                report_lines.append(f"- [ ] {g['item']}: {g['suggestion']}")
            report_lines.append("")
        if low_gaps:
            report_lines.append("### 长期提升（持续进行）\n")
            for g in low_gaps[:5]:
                report_lines.append(f"- [ ] {g['item']}: {g['suggestion']}")
            report_lines.append("")

        report_text = "\n".join(report_lines)

        # 保存文件
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(report_text)

        return report_text

    @staticmethod
    def _score_level(score: float) -> str:
        """根据分数返回等级描述"""
        if score >= 90:
            return "优秀 - 高度匹配"
        elif score >= 80:
            return "良好 - 较好匹配"
        elif score >= 70:
            return "中等 - 基本匹配"
        elif score >= 60:
            return "一般 - 部分匹配"
        elif score >= 50:
            return "偏低 - 匹配度不足"
        else:
            return "较弱 - 匹配度很低"

    @staticmethod
    def _current_time() -> str:
        """返回当前时间字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# 命令行入口
# =============================================================================

def main():
    """命令行入口函数"""
    parser = argparse.ArgumentParser(
        description="简历智能解析与岗位匹配推荐工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python matcher_engine.py --resume my_resume.md --jd target_jd.md
  python matcher_engine.py --resume resume.md --jd jd.md --output report.md --preset tech
  python matcher_engine.py --resume resume.md --jd jd.md --weights skill=0.4 experience=0.3
        """
    )
    parser.add_argument("--resume", "-r", required=True, help="简历文件路径（Markdown/纯文本）")
    parser.add_argument("--jd", "-j", required=True, help="岗位JD文件路径（Markdown/纯文本）")
    parser.add_argument("--output", "-o", help="匹配报告输出文件路径")
    parser.add_argument("--preset", "-p", choices=["tech", "management", "design", "sales", "general"],
                        default=None, help="岗位类型预设权重方案")
    parser.add_argument("--weights", "-w", help="自定义权重（格式：skill=0.4,experience=0.3,...）")
    parser.add_argument("--json", action="store_true", help="以JSON格式输出结果")
    parser.add_argument("--verbose", "-v", action="store_true", help="显示详细输出")

    args = parser.parse_args()

    # 读取输入文件
    try:
        with open(args.resume, "r", encoding="utf-8") as f:
            resume_text = f.read()
    except FileNotFoundError:
        print(f"错误：无法读取简历文件 '{args.resume}'", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.jd, "r", encoding="utf-8") as f:
            jd_text = f.read()
    except FileNotFoundError:
        print(f"错误：无法读取JD文件 '{args.jd}'", file=sys.stderr)
        sys.exit(1)

    # 解析自定义权重
    weights = None
    if args.weights:
        weights = {}
        for pair in args.weights.split(","):
            if "=" in pair:
                key, val = pair.strip().split("=", 1)
                try:
                    weights[key.strip()] = float(val.strip())
                except ValueError:
                    print(f"警告：忽略无效权重值 '{pair}'", file=sys.stderr)

    # 初始化匹配器
    matcher = ResumeJDMatcher(weights=weights, preset=args.preset)

    # 执行匹配
    result = matcher.match(resume_text, jd_text)

    # 输出结果
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        if args.verbose:
            # 解析后的简历和JD数据
            resume_data = matcher.parse_resume(resume_text)
            jd_data = matcher.parse_jd(jd_text)
            print("=== 简历解析结果 ===")
            print(json.dumps(resume_data, ensure_ascii=False, indent=2))
            print("\n=== JD解析结果 ===")
            print(json.dumps(jd_data, ensure_ascii=False, indent=2))
            print()

        # 生成报告
        report = matcher.generate_report(result, output_path=args.output)
        if not args.output:
            print(report)


if __name__ == "__main__":
    main()
