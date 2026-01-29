#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
搜书吧论坛自动登录签到脚本
Usage:
    python checkin.py -u <username> -p <password>
    或设置环境变量 USERNAME 和 PASSWORD
"""

import os
import sys
import re
import argparse
import requests


class AutoCheckin:
    """自动登录签到类（登录即签到）"""

    BASE_URL = "https://pvew5.pver549cn.com"
    ENCODING = "gbk"

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    def _decode(self, resp: requests.Response) -> str:
        return resp.content.decode(self.ENCODING, errors="ignore")

    def _get_formhash(self, content: str) -> str:
        match = re.search(r'name=["\']formhash["\'][^>]*value=["\']([a-f0-9]{8})["\']', content)
        return match.group(1) if match else ""

    def run(self) -> bool:
        """执行登录签到"""
        print("=" * 50)
        print("搜书吧自动登录签到")
        print(f"目标: {self.BASE_URL}")
        print(f"账号: {self.username}")
        print("=" * 50)

        # 1. 获取首页和 formhash
        print("[INFO] 获取首页...")
        try:
            resp = self.session.get(f"{self.BASE_URL}/", timeout=30)
            content = self._decode(resp)
            formhash = self._get_formhash(content)
            if not formhash:
                print("[ERROR] 无法获取 formhash")
                return False
            print(f"[INFO] formhash: {formhash}")
        except Exception as e:
            print(f"[ERROR] 获取首页失败: {e}")
            return False

        # 2. 执行登录（首页快捷登录）
        print("[INFO] 执行登录...")
        login_url = f"{self.BASE_URL}/member.php?mod=logging&action=login&loginsubmit=yes&infloat=yes&lssubmit=yes&inajax=1"
        login_data = {
            "formhash": formhash,
            "referer": f"{self.BASE_URL}/",
            "username": self.username,
            "password": self.password,
            "quickforward": "yes",
            "handlekey": "ls",
            "cookietime": "2592000",
        }

        try:
            login_resp = self.session.post(
                login_url,
                data=login_data,
                timeout=30,
                headers={"X-Requested-With": "XMLHttpRequest", "Referer": f"{self.BASE_URL}/"}
            )
            login_text = self._decode(login_resp)

            # 检查登录结果
            if "location.href" in login_text or "succeed" in login_text:
                print("[INFO] 登录请求已发送")
            elif "密码错误" in login_text or "登录失败" in login_text:
                print(f"[ERROR] 登录失败: {login_text}")
                return False
            elif "错误次数过多" in login_text or "15 分钟" in login_text:
                print("[ERROR] 登录限制：请稍后再试")
                return False

        except Exception as e:
            print(f"[ERROR] 登录请求失败: {e}")
            return False

        # 3. 验证登录状态
        print("[INFO] 验证登录状态...")
        try:
            home_resp = self.session.get(f"{self.BASE_URL}/", timeout=30)
            home_text = self._decode(home_resp)
            uid_match = re.search(r'discuz_uid\s*=\s*["\']?(\d+)', home_text)

            if uid_match and uid_match.group(1) != "0":
                print(f"[SUCCESS] 登录成功! UID: {uid_match.group(1)}")
                print("=" * 50)
                print("[DONE] 签到完成（登录即签到）")
                print("=" * 50)
                return True
            else:
                print("[ERROR] 登录验证失败")
                return False

        except Exception as e:
            print(f"[ERROR] 验证失败: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="搜书吧自动登录签到")
    parser.add_argument("--username", "-u", help="用户名/邮箱")
    parser.add_argument("--password", "-p", help="密码")
    args = parser.parse_args()

    username = args.username or os.environ.get("USERNAME") or os.environ.get("CHECKIN_USERNAME")
    password = args.password or os.environ.get("PASSWORD") or os.environ.get("CHECKIN_PASSWORD")

    if not username or not password:
        print("[ERROR] 请提供登录凭据!")
        print("用法: python checkin.py -u <username> -p <password>")
        sys.exit(1)

    checker = AutoCheckin(username, password)
    success = checker.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
