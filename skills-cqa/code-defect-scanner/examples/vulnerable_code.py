#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
包含多种缺陷和安全漏洞的示例代码

本文件故意包含多种常见的安全漏洞、代码缺陷和代码异味，
用于展示 code-defect-scanner 的扫描能力。

警告：本文件中的代码仅用于演示，绝对不要在生产环境使用！
"""

import os
import pickle
import random
import subprocess
from typing import List, Dict, Optional

# 硬编码敏感信息（CRITICAL）
DATABASE_URL = "postgresql://admin:YOUR_PASSWORD_HERE@db.example.com:5432/mydb"
API_KEY = "sk-YOUR-API-KEY-PLACEHOLDER-REPLACE-ME"
SECRET_KEY = "YOUR-SECRET-KEY-PLACEHOLDER"
ACCESS_TOKEN = "ya29.YOUR-TOKEN-PLACEHOLDER"

# SQL 注入漏洞（CRITICAL）
def get_user(username: str) -> dict:
    query = f"SELECT * FROM users WHERE username='{username}'"
    cursor.execute(query)
    return cursor.fetchall()


# 命令注入漏洞（CRITICAL）
def run_ping(host: str) -> str:
    result = os.system(f"ping -c 4 {host}")
    return str(result)


def execute_script(script_path: str) -> str:
    result = subprocess.run(f"python {script_path}", shell=True, capture_output=True)
    return result.stdout.decode()


def process_user_input(user_data: str) -> object:
    result = eval(user_data)
    return result


# 代码缺陷
def process_data(data: list) -> list:
    result = []
    for item in data:
        try:
            value = int(item)
            result.append(value)
        except:
            pass
    return result


# 重复导入
import json
import json


# 调试代码残留
def debug_function():
    x = 10
    import pdb; pdb.set_trace()
    print(f"调试信息: x = {x}")
    print(f"密码: {SECRET_KEY}")
    return x


# 未使用的变量
def compute_metrics(data: list) -> float:
    total = sum(data)
    count = len(data)
    average = total / count if count > 0 else 0
    unused_var = 42
    return average
