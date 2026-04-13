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
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


class AutoCheckin:
    """自动登录签到类（登录即签到）"""

    PUBLISH_URL = "http://www.soushu2030.com/"
    BASE_URL = ""
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

    def _decode_publish_page(self, resp: requests.Response) -> str:
        encoding = resp.encoding
        if not encoding or encoding.lower() == "iso-8859-1":
            encoding = resp.apparent_encoding or "utf-8"
        return resp.content.decode(encoding, errors="ignore")

    def _extract_meta_refresh_url(self, content: str, base_url: str) -> str:
        match = re.search(
            r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'>]+)',
            content,
            re.IGNORECASE,
        )
        if not match:
            return ""
        return urljoin(base_url, match.group(1).strip())

    def _resolve_base_url(self) -> str:
        url = self.PUBLISH_URL

        for step in range(5):
            print(f"[INFO] 获取最新地址发布页[{step + 1}]: {url}")
            resp = self.session.get(url, timeout=30, allow_redirects=True)
            content = self._decode_publish_page(resp)

            next_url = self._extract_meta_refresh_url(content, resp.url)
            if next_url and next_url.rstrip("/") != resp.url.rstrip("/"):
                url = next_url
                continue

            soup = BeautifulSoup(content, "html.parser")
            latest_link = None
            for link in soup.find_all("a", href=True):
                text = link.get_text(strip=True)
                if "最新地址" in text:
                    latest_link = link
                    break

            if not latest_link:
                for link in soup.find_all("a", href=True):
                    text = link.get_text(strip=True)
                    if "搜书吧" in text:
                        latest_link = link
                        break

            href = latest_link.get("href") if latest_link else ""
            if href and not href.startswith("javascript:"):
                resolved_url = urljoin(resp.url, href).rstrip("/")
                print(f"[INFO] 最新地址: {resolved_url}")
                return resolved_url

            raise ValueError(f"未找到最新地址链接，当前状态码: {resp.status_code}")

        raise ValueError("最新地址解析超过跳转上限")

    def run(self) -> bool:
        """执行登录签到"""
        print("=" * 50)
        print("搜书吧自动登录签到")
        print(f"发布页: {self.PUBLISH_URL}")
        print(f"账号: {self.username}")
        print("=" * 50)

        try:
            self.BASE_URL = self._resolve_base_url()
        except Exception as e:
            print(f"[ERROR] 获取最新地址失败: {e}")
            return False

        print(f"目标: {self.BASE_URL}")

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
