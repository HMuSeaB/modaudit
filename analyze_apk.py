#!/usr/bin/env python3
"""APK/.apks 元信息摸底: 包名/版本/签名证书/签名方案/文件构成/stub .so/可疑注入痕迹。

用法:
    python analyze_apk.py <apk|apks>...            # 标签默认取文件名
    python analyze_apk.py a.apk:标签A b.apks:标签B

依赖: androguard + loguru (pip install -r requirements.txt)
"""
import hashlib
import io
import os
import sys
import tempfile
import zipfile
from collections import defaultdict

from loguru import logger
logger.remove()
from androguard.core.apk import APK

# 文件名级可疑标记: hook 框架 / 签名伪装工具 / 修改器
MARKERS = ['lspatch', 'LSPatch', 'lsposed', 'xposed', 'substrate', 'whale',
           'SandHook', 'sandhook', 'pine', 'Dobby', 'shadowhook',
           'SignatureKiller', 'KillerApplication', 'bin/mt/']


def cert_dates(c):
    """兼容不同 androguard 版本的日期属性名。"""
    b = getattr(c, 'not_valid_before_utc', None) or getattr(c, 'not_valid_before', None)
    a = getattr(c, 'not_valid_after_utc', None) or getattr(c, 'not_valid_after', None)
    return f'{b} -> {a}'


def container_streams(path):
    """产出该输入下所有内层 apk 的 ZipFile 流: .apk 直接开; .apks/zip 下钻一层。"""
    z = zipfile.ZipFile(path)
    inners = [n for n in z.namelist() if n.endswith('.apk') and not n.endswith('.apks')]
    if path.endswith('.apk') or not inners:
        yield z
        return
    for n in inners:
        yield zipfile.ZipFile(io.BytesIO(z.read(n)))


def load_main_apk(path):
    """取主包供 androguard 解析。.apk 直接用;
    .apks/.zip/.zip(套apks) 容器里递归找 base 命名的内层包, 避免误取 SignatureKiller/origin.apk 之类。"""
    if path.endswith('.apk'):
        return path
    z = zipfile.ZipFile(path)
    inners = [n for n in z.namelist() if n.endswith('.apk') and not n.endswith('.apks')]
    if not inners:
        # 容器里还有 .apks(如 zip 套 apks): 下钻一层
        for n in z.namelist():
            if n.endswith('.apks'):
                zi = zipfile.ZipFile(io.BytesIO(z.read(n)))
                sub = [m for m in zi.namelist() if m.endswith('.apk') and not m.endswith('.apks')]
                base = [m for m in sub if os.path.basename(m).startswith('base')]
                if sub:
                    data = zi.read(sorted(base or sub)[0])
                    tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
                    tmp.write(data)
                    tmp.close()
                    return tmp.name
        return path
    base = [n for n in inners if os.path.basename(n).startswith('base')]
    if not base:
        base = [n for n in inners if 'origin.apk' not in n and n.startswith('split')]
    if not base:
        base = [n for n in inners if 'origin.apk' not in n] or inners
    data = z.read(sorted(base)[0])
    tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
    tmp.write(data)
    tmp.close()
    return tmp.name


def analyze(path, label):
    print('=' * 70)
    print(f'### {label}  ({path})')
    try:
        a = APK(load_main_apk(path))
    except Exception as e:
        print('  APK 解析失败:', e)
        return
    print('  package:', a.get_package(),
          'versionName:', a.get_androidversion_name(),
          'versionCode:', a.get_androidversion_code())
    print('  minSdk/targetSdk:', a.get_min_sdk_version(), '/', a.get_target_sdk_version())
    print(f'  签名方案: v1={a.is_signed_v1()} v2={a.is_signed_v2()} v3={a.is_signed_v3()}')
    try:
        for c in a.get_certificates():
            print('  证书 subject:', c.subject.human_friendly)
            print('  证书 issuer :', c.issuer.human_friendly)
            print('  证书 serial :', c.serial_number, ' 有效期:', cert_dates(c))
            fp = c.sha256_fingerprint
            fp = fp if isinstance(fp, str) else fp.hex()
            print('  证书 sha256 :', hashlib.sha256(fp.encode()).hexdigest()[:16], '(指纹摘要)')
    except Exception as e:
        print('  证书解析失败:', e)

    # ---- 文件构成(.apks 会合并统计所有 split) ----
    groups = defaultdict(lambda: [0, 0])
    so_n = so_bytes = total_uncomp = 0
    dex_names, markers = [], defaultdict(int)
    for z in container_streams(path):
        for i in z.infolist():
            if i.filename.endswith('/'):
                continue
            total_uncomp += i.file_size
            top = i.filename.split('/')[0]
            g = groups[top]
            g[0] += 1
            g[1] += i.file_size
            if i.filename.endswith('.so'):
                so_n += 1
                so_bytes += i.file_size
            elif i.filename.endswith('.dex'):
                dex_names.append(i.filename)
            for m in MARKERS:
                if m in i.filename:
                    markers[m] += 1
    print(f'  解压总大小: {total_uncomp / 1048576:.1f} MB')
    print('  顶层条目 (数量, 解压字节):')
    for k, (n, sz) in sorted(groups.items(), key=lambda kv: -kv[1][1])[:10]:
        print(f'    {k:28s} {n:7d} {sz / 1048576:10.1f} MB')
    print(f'  .so: {so_n} 个 / {so_bytes / 1048576:.1f} MB   dex: {len(dex_names)} 个')
    print('  可疑文件名命中:', dict(markers) if markers else '无')


if __name__ == '__main__':
    specs = sys.argv[1:]
    if not specs:
        raise SystemExit(__doc__)
    for spec in specs:
        if os.path.exists(spec):
            path = spec
            label = os.path.basename(path)
        elif len(spec) > 2 and spec[1] == ':' and spec[2] in ('\\', '/'):
            rest = spec[2:]
            if ':' in rest:
                p, _, l = rest.partition(':')
                path = spec[:2] + p
                label = l
            else:
                path = spec
                label = os.path.basename(path)
        elif ':' in spec:
            path, _, label = spec.partition(':')
        else:
            path = spec
            label = os.path.basename(path)
        analyze(path, label or os.path.basename(path))
