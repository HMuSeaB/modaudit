#!/usr/bin/env python3
"""apkpure 历史版本下载器(免账号/免浏览器, 移植自 EFForg/apkeep 的 apkpure.rs)。

原理: apkpure 的移动端 API `https://api.pureapk.com/m/v3/cms/app_version` 返回某包名的
全部版本列表, 版本串后跟着 40+ 位 hex 和下载直链(XAPKJ=打包XAPK)。带专用请求头即可直连,
不走网页(网页才有 Cloudflare)。

用法:
    python apkpure_dl.py --list com.tencent.mm                 # 只列出可用版本
    python apkpure_dl.py com.tencent.mm:8.0.64                 # 下载指定版本(XAPK)
    python apkpure_dl.py com.tencent.mm:8.0.64 com.quark.browser:7.14.2.872 --out official/
    python apkpure_dl.py --arch arm64-v8a com.tencent.mm:8.0.64  # 指定 ABI 过滤

依赖: 仅标准库 + 系统 curl(用 --proxy 走代理, 支持 socks5h://)。
"""
import argparse
import os
import re
import subprocess
import sys

VERSIONS_URL = "https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name={}"
DL_URL_REGEX = r"(X?APKJ)..(https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))"
VERSION_HEADER = "x-cv: 3172501\nx-sv: 29\nx-gp: 1"


def api_headers(abis):
    h = ["x-cv: 3172501", "x-sv: 29", "x-gp: 1"]
    if abis:
        h.append("x-abis: " + ",".join(abis))
    return h


def http_get(url, proxy, abis, extra_headers=None, out=None, referer=None, timeout=3600, resume=False):
    cmd = ["curl", "-sL"]
    if out:
        cmd += ["--max-time", str(timeout)]
        if resume:
            cmd += ["-C", "-"]
    else:
        cmd += ["--max-time", "120"]
    if proxy:
        cmd += ["--proxy", proxy]
    for h in api_headers(abis):
        cmd += ["-H", h]
    if extra_headers:
        for h in extra_headers:
            cmd += ["-H", h]
    if referer:
        cmd += ["-H", "Referer: " + referer]
    cmd += ["-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"]
    if out:
        cmd += ["-o", out, "-w", "%{http_code} %{size_download}", url]
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.stdout
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True)
    return r.stdout.decode("utf-8", "replace")


def download_resumable(url, out, proxy, abis, referer=None, tries=5):
    """断点续传下载, 直到 zip 完整(尾部出现 EOCD)或重试耗尽。"""
    import os
    import time
    for i in range(tries):
        r = http_get(url, proxy, abis, out=out, referer=referer,
                     resume=os.path.exists(out) and os.path.getsize(out) > 0)
        with open(out, "rb") as f:
            f.seek(-30, 2) if os.path.getsize(out) > 30 else f.seek(0)
            tail = f.read()
        if b"PK\x05\x06" in tail:
            return r + " (完整)"
        print(f"   下载不完整({os.path.getsize(out)}B), 续传中... {r}")
        time.sleep(2)
    return r + " (警告: 可能不完整)"


def fetch_versions(pkg, proxy, abis):
    body = http_get(VERSIONS_URL.format(pkg), proxy, abis)
    versions = set(re.findall(r"([a-zA-Z0-9.\-]+):\(([0-9a-f]{40,})", body))
    dls = re.findall(DL_URL_REGEX, body)
    return versions, [d[1] for d in dls], body


def main():
    ap = argparse.ArgumentParser(description="apkpure 历史版本下载器 (apkeep 移植)")
    ap.add_argument("apps", nargs="*", help="包名 或 包名:版本")
    ap.add_argument("--list", action="store_true", help="只列出版本, 不下载")
    ap.add_argument("--out", default=".", help="下载目录")
    ap.add_argument("--proxy", default=os.environ.get("APKTOOL_PROXY", ""),
                    help="curl 代理(也可设环境变量 APKTOOL_PROXY), 如 socks5h://127.0.0.1:7891")
    ap.add_argument("--arch", action="append", help="ABI 过滤, 可多次")
    args = ap.parse_args()

    import os
    os.makedirs(args.out, exist_ok=True)
    for app in args.apps:
        pkg, _, want_ver = app.partition(":")
        print(f"== {pkg}" + (f" @{want_ver}" if want_ver else ""))
        versions, dls, body = fetch_versions(pkg, args.proxy, args.arch)
        print(f"   API 返回版本条目: {len(versions)}  下载链: {len(dls)}")
        if args.list:
            for v, code in sorted(versions):
                print(f"   {v}  ({int(code, 16) if len(code) <= 8 else code})")
            continue
        if not want_ver:
            print("   未指定版本, 跳过下载(用 包名:版本 或 --list 查看)")
            continue
        # 定位目标版本之后最近的下载链 (apkeep: 版本串匹配后第一个 URL)
        m = re.search(r"[^0-9]" + re.escape(want_ver) + r":(?s:.)+?" + DL_URL_REGEX, body)
        if not m:
            print(f"   ✗ 版本 {want_ver} 未在 API 中找到, 试试 --list")
            continue
        url = m.group(2)
        kind = "xapk" if m.group(1) == "XAPKJ" else "apk"
        fname = f"{pkg.replace('.', '_')}_{want_ver}.{kind}"
        out = os.path.join(args.out, fname)
        print(f"   下载: {url[:110]}...")
        r = download_resumable(url, out, args.proxy, args.arch, referer="https://apkpure.com/")
        print(f"   -> {out}  curl: {r}")


if __name__ == "__main__":
    main()
