#!/usr/bin/env python3
"""对比两个 dex 的 map_list: 按"偏移排序后计算各类型段的字节总量", 对比哪一段长大/缩小。

注意: 早期版本按 map_list 条目顺序逐对相减是错的(重建工具会打乱段顺序);
本版本按偏移排序聚合, 与顺序无关。

用法:
    python mapdiff.py <old.dex> <new.dex>

依赖: 仅标准库
"""
import struct
import sys

MAP_NAMES = {0: 'HEADER', 1: 'STRING_ID', 2: 'TYPE_ID', 3: 'PROTO_ID', 4: 'FIELD_ID', 5: 'METHOD_ID',
             6: 'CLASS_DEF', 0x1000: 'MAP_LIST', 0x1001: 'TYPE_LIST', 0x1002: 'ANNOTATION_SET_REF_LIST',
             0x1003: 'ANNOTATION_SET_ITEM', 0x2000: 'CLASS_DATA', 0x2001: 'CODE', 0x2002: 'STRING_DATA',
             0x2003: 'DEBUG_INFO', 0x2004: 'ANNOTATION', 0x2005: 'ENCODED_ARRAY',
             0x2006: 'ANNOTATIONS_DIRECT'}


def section_totals(data):
    (map_off,) = struct.unpack_from('<I', data, 52)
    (n,) = struct.unpack_from('<I', data, map_off)
    items = []
    for i in range(n):
        t, _u, cnt, off = struct.unpack_from('<HHII', data, map_off + 4 + i * 12)
        items.append((t, cnt, off))
    items.sort(key=lambda x: x[2])
    totals = {}
    for j, (t, cnt, off) in enumerate(items):
        end = items[j + 1][2] if j + 1 < len(items) else len(data)
        acc = totals.setdefault(t, [0, 0])
        acc[0] += end - off   # 字节量
        acc[1] += cnt         # 条目数
    return totals


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    a = open(sys.argv[1], 'rb').read()
    b = open(sys.argv[2], 'rb').read()
    sa, sb = section_totals(a), section_totals(b)

    print(f"{'type':24s} {'bytes A':>12s} {'bytes B':>12s} {'delta':>9s}   {'cntA':>7s} {'cntB':>7s}")
    for t in sorted(set(sa) | set(sb)):
        ba, ca = sa.get(t, [0, 0])
        bb, cb = sb.get(t, [0, 0])
        if ba != bb or ca != cb:
            print(f'{MAP_NAMES.get(t, hex(t)):24s} {ba:12d} {bb:12d} {bb - ba:9d}   {ca:7d} {cb:7d}')


if __name__ == '__main__':
    main()
