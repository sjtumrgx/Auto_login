#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Discuz 论坛自动签到脚本
Usage:
    设置环境变量 USERNAME 和 PASSWORD 后运行：
    python checkin.py

    或直接指定参数：
    python checkin.py --username xxx --password xxx
"""

import os
import re
import sys
import time
import argparse
import requests
from functools import wraps


class RateLimitError(Exception):
    """频率限制异常，不应重试"""
    pass


def retry(max_attempts: int = 3, delay: float = 5.0):
    """重试装饰器"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(1, max_attempts + 1):
                try:
                    result = func(*args, **kwargs)
                    if result:
                        return result
                    if attempt < max_attempts:
                        print(f"[RETRY] 第 {attempt}/{max_attempts} 次尝试失败，{delay}秒后重试...")
                        time.sleep(delay)
                except RateLimitError as e:
                    # 频率限制不重试
                    print(f"[ERROR] {e}")
                    return False
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts:
                        print(f"[RETRY] 第 {attempt}/{max_attempts} 次遇到异常: {e}，{delay}秒后重试...")
                        time.sleep(delay)
            if last_exception:
                print(f"[ERROR] 所有重试均失败，最后异常: {last_exception}")
            return False
        return wrapper
    return decorator


class DiscuzCheckin:
    """Discuz 论坛自动签到类"""

    BASE_URL = "https://upn2.fwevasmpet.com"
    ENCODING = "gbk"

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.formhash = ""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": "https://upn2.fwevasmpet.com",
        })

    def _decode_response(self, response: requests.Response) -> str:
        """解码响应内容"""
        return response.content.decode(self.ENCODING, errors="ignore")

    def _get_formhash(self, content: str) -> str:
        """从页面内容中提取 formhash"""
        # 优先从 input 标签获取
        match = re.search(r'name=["\']formhash["\'][^>]*value=["\']([a-f0-9]{8})["\']', content)
        if match:
            return match.group(1)
        # 备用：从其他位置获取
        match = re.search(r'formhash["\s:=]+([a-f0-9]{8})', content)
        return match.group(1) if match else ""

    def _get_loginhash(self, content: str) -> str:
        """从页面内容中提取 loginhash"""
        match = re.search(r'loginhash=([a-zA-Z0-9]+)', content)
        return match.group(1) if match else ""

    def _init_session(self) -> bool:
        """初始化会话，获取必要的 cookies 和 tokens"""
        try:
            print("[INFO] 正在初始化会话...")
            resp = self.session.get(f"{self.BASE_URL}/", timeout=30)
            content = self._decode_response(resp)
            self.formhash = self._get_formhash(content)
            print(f"[INFO] 获取 formhash: {self.formhash}")
            return bool(self.formhash)
        except Exception as e:
            print(f"[ERROR] 初始化会话失败: {e}")
            return False

    @retry(max_attempts=3, delay=5.0)
    def login(self) -> bool:
        """
        执行 Discuz 论坛登录
        Returns:
            bool: 登录是否成功
        """
        print(f"[INFO] 正在登录账号: {self.username}")

        # 获取登录页面
        login_page_url = f"{self.BASE_URL}/member.php?mod=logging&action=login"
        try:
            login_page = self.session.get(login_page_url, timeout=30)
            content = self._decode_response(login_page)

            # 提取必要参数
            formhash = self._get_formhash(content)
            loginhash = self._get_loginhash(content)

            if not formhash:
                print("[WARNING] 未能获取 formhash，使用已有值")
                formhash = self.formhash

            print(f"[INFO] formhash: {formhash}, loginhash: {loginhash}")

        except Exception as e:
            print(f"[ERROR] 获取登录页面失败: {e}")
            return False

        # 构建登录请求
        login_url = f"{self.BASE_URL}/member.php?mod=logging&action=login&loginsubmit=yes"
        if loginhash:
            login_url += f"&loginhash={loginhash}"

        login_data = {
            "formhash": formhash,
            "referer": f"{self.BASE_URL}/",
            "loginfield": "username",
            "username": self.username,
            "password": self.password,
            "questionid": "0",
            "answer": "",
            "cookietime": "2592000",
        }

        try:
            resp = self.session.post(
                login_url,
                data=login_data,
                timeout=30,
                headers={"Referer": login_page_url}
            )
            content = self._decode_response(resp)

            # 检查登录结果（顺序很重要：先检查特殊情况）
            if "密码错误次数过多" in content or "请 15 分钟后" in content:
                raise RateLimitError("登录限制：密码错误次数过多，请 15 分钟后重新登录")

            if "密码错误" in content and "次数过多" not in content:
                print("[ERROR] 登录失败：密码错误")
                return False

            if "用户不存在" in content or "登录失败" in content:
                print("[ERROR] 登录失败：账号不存在或其他错误")
                return False

            if "succeedhandle" in content or "欢迎" in content or "跳转" in content:
                print("[SUCCESS] 登录成功!")
                # 更新 formhash
                new_formhash = self._get_formhash(content)
                if new_formhash:
                    self.formhash = new_formhash
                return True

            # 验证登录状态：访问用户中心
            return self._verify_login()

        except RateLimitError:
            raise  # 重新抛出，让重试装饰器处理
        except Exception as e:
            print(f"[ERROR] 登录请求失败: {e}")
            return False

    def _verify_login(self) -> bool:
        """验证登录状态"""
        try:
            resp = self.session.get(f"{self.BASE_URL}/home.php?mod=space", timeout=30)
            content = self._decode_response(resp)

            # 检查是否显示用户信息
            if "退出" in content or "个人资料" in content or "我的主页" in content:
                print("[SUCCESS] 登录状态验证通过!")
                # 更新 formhash
                new_formhash = self._get_formhash(content)
                if new_formhash:
                    self.formhash = new_formhash
                return True

            # 检查 discuz_uid
            uid_match = re.search(r'discuz_uid\s*=\s*[\'"]?(\d+)', content)
            if uid_match and uid_match.group(1) != "0":
                print(f"[SUCCESS] 登录状态验证通过! UID: {uid_match.group(1)}")
                return True

            print("[WARNING] 无法确认登录状态")
            return False

        except Exception as e:
            print(f"[ERROR] 验证登录状态失败: {e}")
            return False

    @retry(max_attempts=3, delay=5.0)
    def checkin(self) -> bool:
        """
        执行签到（Discuz 论坛签到插件）
        Returns:
            bool: 签到是否成功
        """
        print("[INFO] 开始执行签到...")

        # Discuz 常见签到插件端点
        sign_endpoints = [
            "/plugin.php?id=dsu_paulsign:sign",
            "/plugin.php?id=dc_signin:dc_signin",
            "/plugin.php?id=k_misign:sign",
            "/plugin.php?id=csu_kuq:sign",
        ]

        for endpoint in sign_endpoints:
            try:
                url = f"{self.BASE_URL}{endpoint}"
                print(f"[INFO] 尝试签到页面: {url}")

                resp = self.session.get(url, timeout=30)
                content = self._decode_response(resp)

                # 检查签到页面是否存在
                if "404" in content or "插件不存在" in content:
                    continue

                # 检查是否已签到
                if "已经签到" in content or "今日已签" in content or "您今日已经签到" in content:
                    print("[INFO] 今日已签到!")
                    return True

                # 尝试执行签到
                if self._do_sign(endpoint, content):
                    return True

            except Exception as e:
                print(f"[WARNING] 签到端点 {endpoint} 请求失败: {e}")
                continue

        # 如果常见插件都不存在，尝试查找签到链接
        return self._find_and_sign()

    def _do_sign(self, endpoint: str, page_content: str) -> bool:
        """执行签到操作"""
        # 获取页面中的 formhash
        formhash = self._get_formhash(page_content)
        if not formhash:
            formhash = self.formhash

        # 构建签到请求
        sign_data = {
            "formhash": formhash,
            "qdxq": "kx",  # 心情：开心
            "qdmode": "1",
            "todaysay": "",
            "faession": "1",
        }

        # 常见的签到提交端点
        sign_submit_endpoints = [
            "/plugin.php?id=dsu_paulsign:sign&operation=qiandao&infloat=1",
            "/plugin.php?id=dc_signin:dc_signin&sign_in=1",
            "/plugin.php?id=k_misign:sign&operation=qiandao&infloat=1",
        ]

        for submit_endpoint in sign_submit_endpoints:
            try:
                url = f"{self.BASE_URL}{submit_endpoint}"
                resp = self.session.post(
                    url,
                    data=sign_data,
                    timeout=30,
                    headers={"X-Requested-With": "XMLHttpRequest"}
                )
                content = self._decode_response(resp)

                if self._check_sign_success(content):
                    return True

            except Exception as e:
                continue

        return False

    def _find_and_sign(self) -> bool:
        """从首页查找签到入口并执行"""
        try:
            print("[INFO] 尝试从首页查找签到入口...")
            resp = self.session.get(f"{self.BASE_URL}/", timeout=30)
            content = self._decode_response(resp)

            # 查找签到链接
            sign_patterns = [
                r'href="([^"]*plugin\.php\?id=[^"]*sign[^"]*)"',
                r'href="([^"]*qiandao[^"]*)"',
                r'href="([^"]*签到[^"]*)"',
            ]

            for pattern in sign_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    url = match if match.startswith("http") else f"{self.BASE_URL}/{match}"
                    print(f"[INFO] 发现签到链接: {url}")

                    sign_resp = self.session.get(url, timeout=30)
                    sign_content = self._decode_response(sign_resp)

                    if "已经签到" in sign_content or "今日已签" in sign_content:
                        print("[INFO] 今日已签到!")
                        return True

                    if self._do_sign("", sign_content):
                        return True

            print("[WARNING] 未找到签到入口")
            return False

        except Exception as e:
            print(f"[ERROR] 查找签到入口失败: {e}")
            return False

    def _check_sign_success(self, content: str) -> bool:
        """检查签到是否成功"""
        success_indicators = [
            "签到成功",
            "恭喜",
            "获得",
            "成功",
            "今日已签",
            "已经签到",
        ]

        for indicator in success_indicators:
            if indicator in content:
                print(f"[SUCCESS] 签到成功! ({indicator})")
                return True

        return False

    def run(self) -> bool:
        """执行完整的签到流程"""
        print("=" * 50)
        print("Discuz 论坛自动签到脚本")
        print(f"目标网站: {self.BASE_URL}")
        print(f"用户账号: {self.username}")
        print("=" * 50)

        # 初始化会话
        if not self._init_session():
            print("[WARNING] 会话初始化未完成，继续尝试...")

        # 登录
        if not self.login():
            print("[FATAL] 登录失败，无法继续签到")
            return False

        # 签到
        if not self.checkin():
            print("[WARNING] 签到失败或签到功能不可用")
            # 某些论坛登录即签到，不强制返回失败
            return True

        print("=" * 50)
        print("[DONE] 签到流程完成")
        print("=" * 50)
        return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="Discuz 论坛自动签到脚本")
    parser.add_argument("--username", "-u", help="登录用户名/邮箱")
    parser.add_argument("--password", "-p", help="登录密码")
    args = parser.parse_args()

    # 优先使用命令行参数，其次使用环境变量
    username = args.username or os.environ.get("USERNAME") or os.environ.get("CHECKIN_USERNAME")
    password = args.password or os.environ.get("PASSWORD") or os.environ.get("CHECKIN_PASSWORD")

    if not username or not password:
        print("[ERROR] 请提供登录凭据!")
        print("使用方式:")
        print("  1. 设置环境变量: USERNAME 和 PASSWORD")
        print("  2. 命令行参数: python checkin.py -u <username> -p <password>")
        sys.exit(1)

    checker = DiscuzCheckin(username, password)
    success = checker.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
