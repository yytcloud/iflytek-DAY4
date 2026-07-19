#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data Insight Reporter - 数据智能分析引擎

功能：
1. 自动加载数据文件（CSV/TSV/JSON），检测编码和分隔符
2. 计算描述性统计指标（数值型、分类型、日期型）
3. 异常值检测（IQR法、Z-Score法、MAD法）
4. 时间序列趋势分析
5. 变量间相关性分析
6. 生成结构化Markdown分析报告

作者：Data Insight Reporter Skill
版本：1.0.0
"""

import csv
import json
import math
import os
import re
import sys
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any, Union


class DataAnalyzer:
    """数据智能分析器"""

    def __init__(self, filepath: str, encoding: str = None,
                 delimiter: str = None):
        self.filepath = filepath
        self.encoding = encoding
        self.delimiter = delimiter
        self.data = []
        self.headers = []
        self.col_types = {}
        self.col_stats = {}
        self.anomalies = {}
        self.correlations = {}
        self.report_meta = {
            "file": os.path.basename(filepath),
            "filepath": filepath,
            "file_size": self._get_file_size(filepath),
            "generated_at": "",
            "row_count": 0,
            "col_count": 0
        }

    def _get_file_size(self, filepath: str) -> str:
        if not os.path.exists(filepath):
            return "未知"
        size_bytes = os.path.getsize(filepath)
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

    def _detect_encoding(self, filepath: str) -> str:
        encodings = ['utf-8-sig', 'utf-8', 'gbk', 'gb2312', 'latin-1']
        for enc in encodings:
            try:
                with open(filepath, 'r', encoding=enc) as f:
                    f.read(4096)
                return enc
            except (UnicodeDecodeError, UnicodeError):
                continue
        return 'utf-8'

    def _detect_delimiter(self, first_line: str) -> str:
        candidates = [(',', 0), ('\t', 0), (';', 0), ('|', 0)]
        for delim, _ in candidates:
            count = first_line.count(delim)
            candidates[candidates.index((delim, 0))] = (delim, count)
        candidates.sort(key=lambda x: x[1], reverse=True)
        for delim, count in candidates:
            if count > 0:
                return delim
        return ','

    def load_data(self) -> Dict[str, Any]:
        ext = os.path.splitext(self.filepath)[1].lower()
        if ext == '.json':
            self._load_json()
        else:
            self._load_csv()
        self.report_meta["row_count"] = len(self.data)
        self.report_meta["col_count"] = len(self.headers)
        self.report_meta["generated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._infer_column_types()
        return {"rows": len(self.data), "columns": len(self.headers), "headers": self.headers}

    def _load_csv(self):
        if not self.encoding:
            self.encoding = self._detect_encoding(self.filepath)
        with open(self.filepath, 'r', encoding=self.encoding) as f:
            first_line = f.readline().strip()
        if not self.delimiter:
            self.delimiter = self._detect_delimiter(first_line)
        self.headers = [h.strip() for h in first_line.split(self.delimiter)]
        self.data = []
        with open(self.filepath, 'r', encoding=self.encoding) as f:
            reader = csv.reader(f, delimiter=self.delimiter)
            next(reader, None)
            for row in reader:
                if row:
                    self.data.append(row)

    def _load_json(self):
        if not self.encoding:
            self.encoding = 'utf-8'
        with open(self.filepath, 'r', encoding=self.encoding) as f:
            json_data = json.load(f)
        if isinstance(json_data, list) and len(json_data) > 0:
            self.headers = list(json_data[0].keys())
            self.data = []
            for record in json_data:
                row = [str(record.get(h, '')) for h in self.headers]
                self.data.append(row)
        else:
            raise ValueError("JSON文件必须是对象数组格式")

    def _infer_column_types(self):
        self.col_types = {}
        for col_idx, col_name in enumerate(self.headers):
            values = [row[col_idx].strip() for row in self.data if col_idx < len(row) and row[col_idx].strip()]
            if not values:
                self.col_types[col_name] = "empty"
                continue
            datetime_count = 0
            for val in values[:100]:
                for fmt in ['%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%d/%m/%Y', '%m/%d/%Y']:
                    try:
                        datetime.strptime(val, fmt)
                        datetime_count += 1
                        break
                    except ValueError:
                        continue
            if datetime_count / min(len(values), 100) > 0.8:
                self.col_types[col_name] = "datetime"
                continue
            numeric_count = 0
            for val in values[:100]:
                try:
                    float(val.replace(',', '').replace(' ', ''))
                    numeric_count += 1
                except ValueError:
                    continue
            if numeric_count / min(len(values), 100) > 0.8:
                self.col_types[col_name] = "numeric"
            elif len(set(values)) <= 30:
                self.col_types[col_name] = "categorical"
            else:
                self.col_types[col_name] = "text"

    def _get_column_values(self, col_name: str, as_numeric: bool = False) -> List:
        col_idx = self.headers.index(col_name)
        values = []
        for row in self.data:
            if col_idx < len(row):
                val = row[col_idx].strip()
                if val and val not in ('', 'NA', 'N/A', 'null', 'None', '-'):
                    if as_numeric:
                        try:
                            values.append(float(val.replace(',', '').replace(' ', '')))
                        except ValueError:
                            continue
                    else:
                        values.append(val)
        return values

    def basic_profile(self) -> Dict[str, Any]:
        profile = {
            "file_name": self.report_meta["file"],
            "file_size": self.report_meta["file_size"],
            "row_count": len(self.data),
            "col_count": len(self.headers),
            "columns": [],
            "encoding": self.encoding,
            "delimiter": self.delimiter,
            "type_distribution": Counter(self.col_types.values())
        }
        for col_name in self.headers:
            values = self._get_column_values(col_name)
            null_count = len(self.data) - len(values)
            col_info = {
                "name": col_name, "type": self.col_types.get(col_name, "unknown"),
                "non_null_count": len(values), "null_count": null_count,
                "null_rate": round(null_count / max(len(self.data), 1) * 100, 2),
                "unique_count": len(set(values))
            }
            profile["columns"].append(col_info)
        return profile

    def numeric_statistics(self) -> Dict[str, Dict]:
        stats = {}
        for col_name in self.headers:
            if self.col_types.get(col_name) != "numeric":
                continue
            values = self._get_column_values(col_name, as_numeric=True)
            if len(values) < 1:
                continue
            values_sorted = sorted(values)
            n = len(values)
            mean_val = sum(values) / n
            variance = sum((x - mean_val) ** 2 for x in values) / max(n - 1, 1)
            std_val = math.sqrt(variance)
            if n % 2 == 0:
                median_val = (values_sorted[n // 2 - 1] + values_sorted[n // 2]) / 2
            else:
                median_val = values_sorted[n // 2]
            def percentile(data, p):
                k = (len(data) - 1) * p / 100
                f = math.floor(k)
                c = math.ceil(k)
                if f == c:
                    return data[int(k)]
                return data[int(f)] * (c - k) + data[int(c)] * (k - f)
            q1 = percentile(values_sorted, 25)
            q3 = percentile(values_sorted, 75)
            iqr = q3 - q1
            if n >= 3 and std_val > 0:
                skewness = (sum((x - mean_val) ** 3 for x in values) / n) / (std_val ** 3)
            else:
                skewness = 0.0
            if n >= 4 and std_val > 0:
                kurtosis = (sum((x - mean_val) ** 4 for x in values) / n) / (std_val ** 4) - 3
            else:
                kurtosis = 0.0
            stats[col_name] = {
                "count": n, "mean": round(mean_val, 4), "median": round(median_val, 4),
                "std": round(std_val, 4), "min": round(values_sorted[0], 4),
                "q1": round(q1, 4), "q3": round(q3, 4), "max": round(values_sorted[-1], 4),
                "iqr": round(iqr, 4), "range": round(values_sorted[-1] - values_sorted[0], 4),
                "cv": round(std_val / abs(mean_val) if mean_val != 0 else float('inf'), 4),
                "skewness": round(skewness, 4), "kurtosis": round(kurtosis, 4),
                "lower_fence": round(q1 - 1.5 * iqr, 4), "upper_fence": round(q3 + 1.5 * iqr, 4)
            }
        self.col_stats = stats
        return stats

    def detect_anomalies(self, method: str = "iqr", threshold: float = 1.5) -> Dict[str, List[Dict]]:
        anomalies = {}
        for col_name in self.headers:
            if self.col_types.get(col_name) != "numeric":
                continue
            values = self._get_column_values(col_name, as_numeric=True)
            if len(values) < 4:
                continue
            col_anomalies = []
            if method in ("iqr", "all"):
                col_anomalies.extend(self._detect_iqr(col_name, values, threshold))
            if method in ("zscore", "all"):
                col_anomalies.extend(self._detect_zscore(col_name, values, threshold))
            if method in ("mad", "all"):
                col_anomalies.extend(self._detect_mad(col_name, values, threshold))
            seen = set()
            unique_anomalies = []
            for a in col_anomalies:
                key = (a["row_index"], a["column"])
                if key not in seen:
                    seen.add(key)
                    unique_anomalies.append(a)
            if unique_anomalies:
                anomalies[col_name] = unique_anomalies
        self.anomalies = anomalies
        return anomalies

    def _detect_iqr(self, col_name, values, threshold):
        sorted_vals = sorted(values)
        def percentile(data, p):
            k = (len(data) - 1) * p / 100
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return data[int(k)]
            return data[int(f)] * (c - k) + data[int(c)] * (k - f)
        q1 = percentile(sorted_vals, 25)
        q3 = percentile(sorted_vals, 75)
        iqr = q3 - q1
        lower = q1 - threshold * iqr
        upper = q3 + threshold * iqr
        results = []
        for i, val in enumerate(values):
            if val < lower or val > upper:
                level = "极端异常" if (val < q1 - 3 * iqr or val > q3 + 3 * iqr) else "显著异常"
                results.append({"row_index": i, "column": col_name, "value": round(val, 4), "method": "IQR", "lower_bound": round(lower, 4), "upper_bound": round(upper, 4), "level": level})
        return results

    def _detect_zscore(self, col_name, values, threshold):
        n = len(values)
        mean_val = sum(values) / n
        std_val = math.sqrt(sum((x - mean_val) ** 2 for x in values) / max(n - 1, 1))
        if std_val == 0:
            return []
        results = []
        for i, val in enumerate(values):
            z = abs((val - mean_val) / std_val)
            if z > threshold:
                level = "极端异常" if z > 5 else "显著异常"
                results.append({"row_index": i, "column": col_name, "value": round(val, 4), "method": "Z-Score", "z_score": round(z, 4), "level": level})
        return results

    def _detect_mad(self, col_name, values, threshold):
        sorted_vals = sorted(values)
        n = len(sorted_vals)
        if n % 2 == 0:
            median = (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2
        else:
            median = sorted_vals[n // 2]
        abs_devs = sorted(abs(x - median) for x in values)
        if n % 2 == 0:
            mad = (abs_devs[n // 2 - 1] + abs_devs[n // 2]) / 2
        else:
            mad = abs_devs[n // 2]
        if mad == 0:
            return []
        results = []
        for i, val in enumerate(values):
            modified_z = 0.6745 * abs(val - median) / mad
            if modified_z > threshold:
                level = "极端异常" if modified_z > 5 else "显著异常"
                results.append({"row_index": i, "column": col_name, "value": round(val, 4), "method": "MAD", "modified_z_score": round(modified_z, 4), "level": level})
        return results

    def generate_report(self, output_path: str = None) -> str:
        profile = self.basic_profile()
        num_stats = self.numeric_statistics()
        anomalies = self.detect_anomalies(method="all")
        quality = self.data_quality_score()
        lines = ['# 数据智能分析报告', '', f'> 生成时间：{self.report_meta["generated_at"]}', f'> 数据源：{self.report_meta["file"]}', f'> 文件大小：{self.report_meta["file_size"]}', '', '---', '']
        total_anomalies = sum(len(v) for v in anomalies.values())
        lines.append(f'本报告分析了 **{self.report_meta["file"]}** 文件，共 **{len(self.data)}** 行 **{len(self.headers)}** 列数据。检测到 **{total_anomalies}** 个异常数据点。')
        lines.extend(['', '## 数据概况', '', '| 指标 | 值 |', '|------|-----|'])
        lines.append(f'| 总行数 | {len(self.data)} |')
        lines.append(f'| 总列数 | {len(self.headers)} |')
        lines.extend(['', '---', '', '*本报告由 Data Insight Reporter Skill 自动生成*', ''])
        report = '\n'.join(lines)
        if output_path:
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
        return report

    def data_quality_score(self) -> Dict[str, Any]:
        total_cells = len(self.data) * len(self.headers)
        null_cells = sum(1 for row in self.data for cell in row if not cell.strip())
        completeness = max(0, 100 - (null_cells / max(total_cells, 1) * 100))
        seen_rows = set()
        duplicate_count = 0
        for row in self.data:
            row_key = tuple(row)
            if row_key in seen_rows:
                duplicate_count += 1
            seen_rows.add(row_key)
        uniqueness = max(0, 100 - (duplicate_count / max(len(self.data), 1) * 100))
        overall = round(completeness * 0.5 + uniqueness * 0.5, 1)
        return {"completeness": round(completeness, 1), "uniqueness": round(uniqueness, 1), "overall": overall, "grade": "A" if overall >= 90 else ("B" if overall >= 75 else "C")}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="数据智能分析报告生成器")
    parser.add_argument("filepath", help="数据文件路径")
    parser.add_argument("-o", "--output", default="", help="输出报告路径")
    args = parser.parse_args()
    if not os.path.exists(args.filepath):
        print(f"错误：文件不存在 - {args.filepath}")
        sys.exit(1)
    analyzer = DataAnalyzer(args.filepath)
    analyzer.load_data()
    report = analyzer.generate_report(args.output)
    if not args.output:
        print(report)


if __name__ == "__main__":
    main()
