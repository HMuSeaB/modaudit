#!/usr/bin/env python3
"""方法级语义对比: 用 androguard 反汇编两个 dex, 按 (类名, 方法名, 描述) 对齐后逐方法
比较指令序列哈希, 找出真正被改/新增/删除的方法; 可选扫描某字段的全部读写点(xref)。

这是"排除 dex 重建噪音、找真实改动"的可靠手段(条目重排/偏移变化不影响结果)。

用法:
    python andro_diff.py <old.dex> <new.dex> [--field-ref 'La3;->b1']

    --field-ref 扫描两个 dex 中引用该字段的指令(如 sget/sput), 模式形如 'La3;->b1' 或
                'Lcom/tencent/mm/sdk/platformtools/a3;->b1'(取子串匹配)

依赖: androguard + loguru。大 dex 约需 1-2 分钟。
"""
import argparse
import hashlib

from loguru import logger
logger.remove()
from androguard.misc import AnalyzeDex

FIELD_OPS = ('sget', 'sput', 'iget', 'iput')


def method_hashes(path):
    _, d, _ = AnalyzeDex(path)
    out = {}
    for m in d.get_methods():
        key = (m.get_class_name(), m.get_name(), m.get_descriptor())
        try:
            disasm = ''.join(i.get_output() for i in m.get_instructions())
        except Exception as e:              # 指令解析失败的兜底, 避免整跑崩掉
            disasm = f'<ERR {e}>'
        out[key] = hashlib.md5(disasm.encode()).hexdigest()
    return out


def field_xrefs(path, pattern):
    _, d, _ = AnalyzeDex(path)
    xrefs = set()
    for m in d.get_methods():
        try:
            for i in m.get_instructions():
                if i.get_name().startswith(FIELD_OPS) and pattern in i.get_output():
                    xrefs.add((m.get_class_name(), m.get_name(), m.get_descriptor(),
                               i.get_name(), i.get_output()))
        except Exception:
            pass
    return xrefs


def main():
    ap = argparse.ArgumentParser(description='方法级语义对比 + 字段 xref 扫描')
    ap.add_argument('old_dex')
    ap.add_argument('new_dex')
    ap.add_argument('--field-ref', help="可选: 扫描引用该字段的指令, 如 'La3;->b1'")
    args = ap.parse_args()

    print('loading A:', args.old_dex)
    ma = method_hashes(args.old_dex)
    print('loading B:', args.new_dex)
    mb = method_hashes(args.new_dex)

    ka, kb = set(ma), set(mb)
    only_a, only_b = ka - kb, kb - ka
    print(f'仅 A 有: {len(only_a)}  仅 B 有: {len(only_b)}')
    for k in sorted(only_a)[:20]:
        print('   -', k[0], '->', k[1], k[2])
    for k in sorted(only_b)[:20]:
        print('   +', k[0], '->', k[1], k[2])

    changed = [k for k in (ka & kb) if ma[k] != mb[k]]
    print(f'\n字节码变化的方法: {len(changed)}')
    for k in sorted(changed):
        print('   *', k[0], '->', k[1], k[2])

    if args.field_ref:
        print(f'\n== xref: {args.field_ref}')
        for cls, name, desc, op, out in sorted(field_xrefs(args.old_dex, args.field_ref)
                                               | field_xrefs(args.new_dex, args.field_ref)):
            print(f'   [{op}] {cls} -> {name}{desc}\n       {out}')


if __name__ == '__main__':
    main()
