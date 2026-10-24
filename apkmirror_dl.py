#!/usr/bin/env python3
"""apkmirror 静默下载器 —— Playwright 驱动真 Chromium, 全程无弹窗。

为什么需要它: apkmirror 的网页有 Cloudflare 挑战, 文件在 *.r2.cloudflarestorage.com 上,
该主机对一切非浏览器 TLS 指纹(curl/python-openssl/curl_cffi 伪装 Chrome 均实测)直接
握手失败 —— 只有真 Chromium 内核能过。Playwright 的 expect_download 可以把下载静默
落到指定目录( unlike IAB 内嵌浏览器, 不弹保存对话框)。

用法:
    # variant 页直链(推荐, 从 release 页复制)
    python apkmirror_dl.py "https://www.apkmirror.com/apk/wechat/wechat/wechat-8-0-64-release/wechat-8-0-64-android-apk-download/"
    # release 页 + 自动挑 variant
    python apkmirror_dl.py "https://www.apkmirror.com/apk/google-inc/youtube/youtube-20-44-36-release/" --arch arm64-v8a
    # 其他参数
    --out DIR       保存目录(默认 ./official)
    --headless      无头模式(CF 可能拦, 默认有头可人工过验证)
    --no-proxy      不走代理
    --proxy URI     代理(默认取环境变量 APKTOOL_PROXY, 未设则不走代理)

依赖: playwright (pip install playwright && python -m playwright install chromium)
"""
import argparse
import os
import sys
import time


def log(*a):
    print(*a, flush=True)


def main():
    ap = argparse.ArgumentParser(description='apkmirror 静默下载器 (Playwright)')
    ap.add_argument('url', help='apkmirror variant 页或 release 页 URL')
    ap.add_argument('--out', default='official')
    ap.add_argument('--arch', default='arm64-v8a', help='release 页自动选 variant 时的关键字')
    ap.add_argument('--headless', action='store_true', help='无头模式(CF 可能拦, 默认有头)')
    ap.add_argument('--proxy', default=os.environ.get('APKTOOL_PROXY', ''))
    ap.add_argument('--no-proxy', action='store_true')
    ap.add_argument('--timeout', type=int, default=1800, help='下载超时秒数')
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    os.makedirs(args.out, exist_ok=True)
    launch_kw = dict(headless=args.headless)
    if not args.headless:
        # 有头是过 CF 的前提(headless 被 apkmirror 的 CF 硬拒),
        # 但可以把窗口挪出屏幕外 —— 对 CF 仍是有头真浏览器, 对用户不可见
        launch_kw['args'] = ['--window-position=-32000,-32000']
    if not args.no_proxy:
        launch_kw['proxy'] = {'server': args.proxy}

    with sync_playwright() as p:
        try:
            # 优先驱动系统真 Chrome(对 CF 最友好, 无需下载浏览器)
            browser = p.chromium.launch(channel='chrome', **launch_kw)
        except Exception:
            browser = p.chromium.launch(**launch_kw)
        ctx = browser.new_context(
            accept_downloads=True,
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                       '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            locale='zh-CN',
            viewport={'width': 1366, 'height': 900},
        )
        page = ctx.new_page()
        log('== 打开', args.url)
        page.goto(args.url, wait_until='domcontentloaded', timeout=60000)

        # Cloudflare 挑战: 等它自己过; headful 时留出人工点击时间
        deadline = time.time() + (120 if not args.headless else 45)
        while time.time() < deadline:
            t = page.title()
            if '请稍候' not in t and 'just a moment' not in t.lower():
                break
            log('   Cloudflare 验证中…', t)
            time.sleep(3)
        log('   标题:', page.title())

        url = page.url
        if url.rstrip('/').endswith('-release'):
            # release 页 -> 按"行文本含 arch"挑 variant, 优先普通 APK 而非 BUNDLE
            links = page.locator('a[href*="-android-apk-download"]')
            n = links.count()
            log(f'== release 页共 {n} 个 variant 链接')
            chosen = None
            fallback_apk = None
            for i in range(n):
                a = links.nth(i)
                href = a.get_attribute('href')
                if href.endswith('#disqus_thread'):
                    continue
                try:
                    row = a.evaluate('e => (e.closest("tr") || e.closest("li") || e.closest("div.w-card") || e.parentElement)?.innerText || ""')
                except Exception:
                    row = a.inner_text()
                is_bundle = 'BUNDLE' in row.upper()
                hit = args.arch in row
                log(f'   [{i}] hit={hit} bundle={is_bundle} {href}  | {row[:80]!r}')
                if hit and chosen is None:
                    chosen = href
                if not is_bundle and fallback_apk is None:
                    fallback_apk = href
            if not chosen:
                chosen = fallback_apk  # arch 不在行文本里时, 退而选普通 APK(单包, 适合作 diff 底包)
            if not chosen:
                raise SystemExit('没有可用 variant, 换 --arch 或直接给 variant 页 URL')
            log('== 选择 variant:', chosen)
            page.goto('https://www.apkmirror.com' + chosen, wait_until='domcontentloaded', timeout=60000)
            time.sleep(2)

        # 触发下载并等待
        key = page.locator('a[href*="download/?key="]').first
        href = key.get_attribute('href')
        log('== 下载入口:', href)
        with page.expect_download(timeout=args.timeout * 1000) as dl_info:
            page.goto('https://www.apkmirror.com' + href, wait_until='domcontentloaded', timeout=60000)
        dl = dl_info.value
        target = os.path.join(args.out, dl.suggested_filename)
        dl.save_as(target)
        size = os.path.getsize(target)
        log(f'== 完成: {target}  {size/1048576:.1f} MB')
        browser.close()


if __name__ == '__main__':
    main()
