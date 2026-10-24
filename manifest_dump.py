#!/usr/bin/env python3
"""导出 AndroidManifest 的组件/进程/禁用项结构, 用于检查修改版是否动过组件。

用法:
    python manifest_dump.py <apk|apks>

输出: 各类组件计数、按 android:process 归组的分布、enabled=false 的组件、
      application 类名 / appComponentFactory。
依赖: androguard + loguru
"""
import argparse
import os
import tempfile
import zipfile
from collections import Counter

from loguru import logger
logger.remove()
from androguard.core.apk import APK

NS = '{http://schemas.android.com/apk/res/android}'


def load_apk(path):
    """主包路径: .apk 直接返回; 容器挑 base 命名的内层包(排除 SignatureKiller/origin.apk)。"""
    if path.endswith('.apk'):
        return path
    z = zipfile.ZipFile(path)
    inners = [n for n in z.namelist() if n.endswith('.apk') and not n.endswith('.apks')]
    if not inners:
        return path
    base = [n for n in inners if os.path.basename(n).startswith('base')]
    if not base:
        base = [n for n in inners if 'origin.apk' not in n] or inners
    data = z.read(sorted(base)[0])
    tmp = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
    tmp.write(data)
    tmp.close()
    return tmp.name


def main():
    ap = argparse.ArgumentParser(description='manifest 组件/进程/禁用项导出')
    ap.add_argument('path')
    args = ap.parse_args()

    a = APK(load_apk(args.path))
    print('package:', a.get_package(), a.get_androidversion_name())
    app = a.get_android_manifest_xml().find('application')

    counts, procs, disabled = Counter(), Counter(), []
    for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        for el in app.findall(tag):
            counts[tag] += 1
            procs[el.get(NS + 'process') or '(main)'] += 1
            if el.get(NS + 'enabled') == 'false':
                disabled.append(f'{tag}:{el.get(NS + "name")}')

    print('组件计数:', dict(counts))
    print('进程分布:')
    for p, n in procs.most_common():
        print(f'   {p}: {n}')
    print(f'enabled=false 组件: {len(disabled)} 个')
    for d in disabled:
        print('   disabled:', d)
    for attr in ('name', 'appComponentFactory'):
        v = app.get(NS + attr)
        if v:
            print(f'application @{attr} = {v}')


if __name__ == '__main__':
    main()
