#!/usr/bin/env python3
"""对 .apks(split APK 集合) 或含多个 apk 的目录做"split 感知"的全量 v1 摘要校验。

背景: 修改者常把官方单 apk 重切为 base + 各 split 后保留原 MANIFEST.MF。
base.apk 里引用的一部分文件其实被移进了 split, 直接跑 verify_v1.py 会把它们误报为"删除"。
本脚本把每个引用项按位置分派:
  - 在 base 或任一 split 中找到 -> 用该 apk 的实际内容校验摘要
  - 哪里都找不到 -> 判定"真删除"

用法:
    python verify_v1_full.py <xxx.apks | 含*.apk的目录> [--samples N] [--extract-dir DIR]

依赖: 仅标准库。
"""
import argparse
import base64
import glob
import hashlib
import os
import zipfile
from collections import Counter


def parse_manifest(text):
    """解析 MANIFEST.MF, 正确处理 72 字符续行。"""
    lines = []
    for line in text.splitlines():
        if line.startswith(' ') and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    entries, cur = {}, None
    for line in lines:
        low = line.lower()
        if low.startswith('name:'):
            cur = line[5:].strip()
        elif (low.startswith('sha-1-digest:') or low.startswith('sha-256-digest:')) and cur is not None:
            entries[cur] = (line.split(':', 1)[1].strip(), 'sha256' if '256' in low else 'sha1')
            cur = None
    return entries


def collect_apks(target, extract_dir=None):
    """返回 [base.apk 优先, 其余 split]。.apks 默认解到系统临时目录(避免污染输入目录)。"""
    if os.path.isdir(target):
        apks = sorted(glob.glob(os.path.join(target, '*.apk')))
    else:
        if extract_dir is None:
            import tempfile
            digest = hashlib.md5(os.path.abspath(target).encode()).hexdigest()[:10]
            extract_dir = os.path.join(tempfile.gettempdir(), f'apks_{digest}')
        if not os.path.exists(extract_dir):
            zipfile.ZipFile(target).extractall(extract_dir)
        apks = sorted(glob.glob(os.path.join(extract_dir, '*.apk')))
    if not apks:
        raise SystemExit(f'{target} 中没有找到 *.apk')
    bases = [p for p in apks if os.path.basename(p).startswith('base')]
    if bases:
        apks.remove(bases[0])
        apks.insert(0, bases[0])
    return apks


def main():
    ap = argparse.ArgumentParser(description='split 集合全量 v1 摘要校验')
    ap.add_argument('target', help='.apks 文件或包含 *.apk 的目录')
    ap.add_argument('--samples', type=int, default=20, help='每类最多打印的样例数')
    ap.add_argument('--extract-dir', help='.apks 的解包目录(默认系统临时目录, 复用已有解包)')
    args = ap.parse_args()

    apks = collect_apks(args.target, args.extract_dir)
    print('参与校验的 apk:')
    for p in apks:
        print('   ', os.path.basename(p))
    zbase = zipfile.ZipFile(apks[0])
    splits = {os.path.basename(p): zipfile.ZipFile(p) for p in apks[1:]}
    split_of = {}
    for sp, z in splits.items():
        for n in z.namelist():
            split_of.setdefault(n, sp)

    names_base = set(zbase.namelist())
    if 'META-INF/MANIFEST.MF' not in names_base:
        raise SystemExit('base.apk 无 v1 签名(META-INF/MANIFEST.MF 不存在), 无法校验。')
    entries = parse_manifest(zbase.read('META-INF/MANIFEST.MF').decode('utf-8', 'replace'))

    n_base_match = n_split_match = 0
    modified, deleted = [], []
    for name, (digest, algo) in entries.items():
        n = name[2:] if name.startswith('./') else name
        if n in names_base:
            z, loc = zbase, 'base'
        elif n in split_of:
            z, loc = splits[split_of[n]], split_of[n]
        else:
            deleted.append(n)
            continue
        h = hashlib.sha256() if algo == 'sha256' else hashlib.sha1()
        h.update(z.read(n))
        if base64.b64encode(h.digest()).decode() == digest:
            if loc == 'base':
                n_base_match += 1
            else:
                n_split_match += 1
        else:
            modified.append((n, loc))

    print(f"manifest 引用: {len(entries)}  base内一致={n_base_match}  split内一致={n_split_match}")
    print(f"被修改={len(modified)}:")
    for n, loc in modified:
        print(f"   * [{loc}] {n}")
    if deleted:
        print(f"删除={len(deleted)} (按顶层目录统计):")
        for t, c in Counter(n.split('/')[0] for n in deleted).most_common(20):
            print(f"   {t}: {c}")
        for n in deleted[:args.samples]:
            print("   -", n)


if __name__ == '__main__':
    main()
