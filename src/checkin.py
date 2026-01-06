#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动签到脚本
Usage:
    设置环境变量 USERNAME 和 PASSWORD 后运行：
    python checkin.py

    或直接指定参数：
    python checkin.py --username xxx --password xxx
"""

import os
import sys
import argparse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class AutoCheckin:
    """自动签到类"""

    BASE_URL = "https://upn2.fwevasmpet.com"

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    def _get_csrf_token(self, url: str) -> str | None:
        """获取 CSRF token"""
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            # 常见的 CSRF token 查找方式
            csrf_input = soup.find("input", {"name": "_token"}) or \
                        soup.find("input", {"name": "csrf_token"}) or \
                        soup.find("input", {"name": "_csrf"})

            if csrf_input:
                return csrf_input.get("value")

            # 尝试从 meta 标签获取
            csrf_meta = soup.find("meta", {"name": "csrf-token"})
            if csrf_meta:
                return csrf_meta.get("content")

        except Exception as e:
            print(f"[WARNING] 获取 CSRF token 失败: {e}")

        return None

    def login(self) -> bool:
        """
        执行登录
        Returns:
            bool: 登录是否成功
        """
        login_url = urljoin(self.BASE_URL, "/auth/login")

        print(f"[INFO] 正在访问登录页面: {login_url}")

        # 获取登录页面和可能的 CSRF token
        csrf_token = self._get_csrf_token(login_url)

        # 构建登录数据
        login_data = {
            "email": self.username,
            "passwd": self.password,
            "remember_me": "on",
        }

        # 如果存在 CSRF token，添加到请求数据
        if csrf_token:
            login_data["_token"] = csrf_token
            print("[INFO] 已获取 CSRF token")

        # 尝试不同的登录端点
        login_endpoints = [
            "/auth/login",
            "/user/login",
            "/login",
            "/api/auth/login",
        ]

        for endpoint in login_endpoints:
            try:
                url = urljoin(self.BASE_URL, endpoint)
                print(f"[INFO] 尝试登录端点: {url}")

                resp = self.session.post(
                    url,
                    data=login_data,
                    timeout=30,
                    allow_redirects=True
                )

                # 检查登录是否成功
                if self._check_login_success(resp):
                    print("[SUCCESS] 登录成功!")
                    return True

            except requests.RequestException as e:
                print(f"[WARNING] 登录端点 {endpoint} 请求失败: {e}")
                continue

        print("[ERROR] 所有登录尝试均失败")
        return False

    def _check_login_success(self, response: requests.Response) -> bool:
        """检查登录是否成功"""
        # 检查响应内容中的成功标识
        success_indicators = [
            "登录成功",
            "login success",
            "dashboard",
            "用户中心",
            "我的账户",
            '"ret":1',
            '"code":0',
            '"success":true',
        ]

        fail_indicators = [
            "密码错误",
            "用户不存在",
            "登录失败",
            "login fail",
            "invalid",
            "error",
        ]

        content = response.text.lower()

        # 检查失败标识
        for indicator in fail_indicators:
            if indicator.lower() in content:
                return False

        # 检查成功标识
        for indicator in success_indicators:
            if indicator.lower() in content:
                return True

        # 检查是否重定向到用户页面
        if "/user" in response.url or "/dashboard" in response.url:
            return True

        # 检查 cookies 是否包含登录凭证
        if any(c for c in self.session.cookies if "token" in c.name.lower() or "session" in c.name.lower()):
            return True

        return False

    def checkin(self) -> bool:
        """
        执行签到
        Returns:
            bool: 签到是否成功
        """
        # 常见的签到端点
        checkin_endpoints = [
            "/user/checkin",
            "/user/sign",
            "/checkin",
            "/sign",
            "/api/user/checkin",
        ]

        print("[INFO] 开始执行签到...")

        for endpoint in checkin_endpoints:
            try:
                url = urljoin(self.BASE_URL, endpoint)
                print(f"[INFO] 尝试签到端点: {url}")

                resp = self.session.post(url, timeout=30)

                if self._check_checkin_success(resp):
                    print(f"[SUCCESS] 签到成功! 响应: {resp.text[:200]}")
                    return True

            except requests.RequestException as e:
                print(f"[WARNING] 签到端点 {endpoint} 请求失败: {e}")
                continue

        # 如果 POST 都失败，尝试 GET 请求（某些站点用 GET）
        for endpoint in checkin_endpoints:
            try:
                url = urljoin(self.BASE_URL, endpoint)
                resp = self.session.get(url, timeout=30)

                if self._check_checkin_success(resp):
                    print(f"[SUCCESS] 签到成功 (GET)! 响应: {resp.text[:200]}")
                    return True

            except requests.RequestException as e:
                continue

        print("[ERROR] 所有签到尝试均失败")
        return False

    def _check_checkin_success(self, response: requests.Response) -> bool:
        """检查签到是否成功"""
        success_indicators = [
            "签到成功",
            "获得",
            "checkin success",
            "已签到",
            "签到完成",
            '"ret":1',
            '"code":0',
            '"success":true',
            "msg",  # 通常有返回消息说明成功
        ]

        already_indicators = [
            "已经签到",
            "already",
            "重复签到",
            "今日已签",
        ]

        content = response.text.lower()

        # 已经签到过也算成功
        for indicator in already_indicators:
            if indicator.lower() in content:
                print("[INFO] 今日已签到")
                return True

        # 检查成功标识
        for indicator in success_indicators:
            if indicator.lower() in content:
                return True

        return False

    def run(self) -> bool:
        """
        执行完整的签到流程
        Returns:
            bool: 整体流程是否成功
        """
        print("=" * 50)
        print("自动签到脚本启动")
        print(f"目标网站: {self.BASE_URL}")
        print(f"用户账号: {self.username}")
        print("=" * 50)

        # 登录
        if not self.login():
            print("[FATAL] 登录失败，无法继续签到")
            return False

        # 签到
        if not self.checkin():
            print("[WARNING] 签到失败")
            return False

        print("=" * 50)
        print("[DONE] 签到流程完成")
        print("=" * 50)
        return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="自动签到脚本")
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

    checker = AutoCheckin(username, password)
    success = checker.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
