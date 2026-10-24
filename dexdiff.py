#!/usr/bin/env python3
"""快速对比两个 dex: 头部各段数量 + 字符串池的增删。纯标准库, 秒级完成。

用途: 先用它看"改动是否涉及字符串/方法数/字段数"; 需要方法级语义对比时再上 andro_diff.py。

用法:
    python dexdiff.py <old.dex> <new.dex>

依赖: 仅标准库
"""
import struct
import sys

FIELDS = ['file_size', 'header_size', 'endian_tag', 'link_size', 'link_off', 'map_off',
          'string_ids_size', 'string_ids_off', 'type_ids_size', 'type_ids_off',
          'proto_ids_size', 'proto_ids_off', 'field_ids_size', 'field_ids_off',
          'method_ids_size', 'method_ids_off', 'class_defs_size', 'class_defs_off',
          'data_size', 'data_off']


def header(data):
    return dict(zip(FIELDS, struct.unpack_from('<20I', data, 32)))


def uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7


def strings(data, h):
    out = []
    for i in range(h['string_ids_size']):
        (so,) = struct.unpack_from('<I', data, h['string_ids_off'] + i * 4)
        _, p = uleb128(data, so)          # 跳过 uleb128 的 utf16 长度
        end = data.index(b'\x00', p)
        out.append(data[p:end].decode('utf-8', 'replace'))
    return out


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    a = open(sys.argv[1], 'rb').read()
    b = open(sys.argv[2], 'rb').read()
    ha, hb = header(a), header(b)

    print('== 头部段数量对比')
    for k in FIELDS:
        if ha[k] != hb[k]:
            print(f'   {k}: {ha[k]} -> {hb[k]} (delta {hb[k] - ha[k]})')

    sa, sb = strings(a, ha), strings(b, hb)
    added, removed = set(sb) - set(sa), set(sa) - set(sb)
    print(f'\n== 字符串池: old={len(sa)} new={len(sb)} 新增={len(added)} 删除={len(removed)}')
    for s in sorted(added)[:80]:
        print('   +', s)
    for s in sorted(removed)[:80]:
        print('   -', s)


if __name__ == '__main__':
    main()
