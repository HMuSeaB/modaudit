#!/usr/bin/env python3
"""在 apk 的全部 dex 中扫描某个字段的定义与引用(xref)。

用途: 判断"注入的字段"有没有代码读写(孤儿字段 = 毒字段手法)、被哪些类读写。
比 andro_diff.py --field-ref 多了跨 dex 扫描(字段引用可跨 dex)和定义类字段清单。

用法:
    python xref_field.py <apk> '<类描述符>;-><字段名>' [--tmp DIR]

示例:
    python xref_field.py base.apk 'a3;->b1'
    python xref_field.py app.apk 'Lcom/tencent/mm/sdk/platformtools/a3;->b1'

依赖: androguard + loguru
"""
import argparse
import os
import zipfile

from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex

FIELD_OPS = ('sget', 'sput', 'iget', 'iput')


def dump_dexes(apk_path, tmp):
    os.makedirs(tmp, exist_ok=True)
    z = zipfile.ZipFile(apk_path)
    paths = []
    for n in sorted(zn for zn in z.namelist()
                    if zn.startswith('classes') and zn.endswith('.dex')):
        p = os.path.join(tmp, os.path.basename(n))
        if not os.path.exists(p):
            with open(p, 'wb') as f:
                f.write(z.read(n))
        paths.append((n, p))
    return paths


def main():
    ap = argparse.ArgumentParser(description='全 dex 字段 xref 扫描')
    ap.add_argument('apk')
    ap.add_argument('pattern', help="字段引用模式, 如 'a3;->b1' (子串匹配)")
    ap.add_argument('--tmp', default='xref_dex_tmp', help='dex 解包缓存目录')
    args = ap.parse_args()

    class_part, _, field_part = args.pattern.partition('->')
    class_part = class_part.strip().lstrip('L').rstrip(';')
    field_part = field_part.strip()          # 允许只给类(空字段名)做纯 xref 扫描

    dexes = dump_dexes(args.apk, args.tmp)
    print(f'{args.apk}: {len(dexes)} 个 dex')

    definers, xrefs = [], []
    for name, path in dexes:
        _, d, _ = AnalyzeDex(path)
        for c in d.get_classes():
            if class_part in c.get_name() and field_part:
                fields = [(f.get_name(), f.get_descriptor()) for f in c.get_fields()]
                if any(fn == field_part for fn, _fd in fields):
                    definers.append((name, c.get_name(), fields))
        if field_part:
            needle = f'{class_part};->{field_part}'
        else:
            needle = f'{class_part};->'
        for m in d.get_methods():
            try:
                for i in m.get_instructions():
                    if i.get_name().startswith(FIELD_OPS) and needle in i.get_output():
                        xrefs.append((name, m.get_class_name(), m.get_name(),
                                      m.get_descriptor(), i.get_name(), i.get_output()))
            except Exception:
                pass

    print(f'定义了该字段的类: {len(definers)} 个')
    for dex_name, cls, fields in definers:
        print(f'  {cls} ({dex_name}) 共 {len(fields)} 字段')
        for fn, fd in fields:
            print(f'      {fd} {fn}')
    print(f'\nxref 到 "{args.pattern}": {len(xrefs)} 处')
    for n, cls, mn, md, op, out in xrefs:
        print(f'   [{op}] {n}: {cls} -> {mn}{md}')
        print(f'       {out}')


if __name__ == '__main__':
    main()
