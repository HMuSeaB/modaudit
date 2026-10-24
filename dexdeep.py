#!/usr/bin/env python3
"""对比两个 dex 的 field_ids(按 类/类型 计数, 与重排无关)与 class_data 的字段变化。

可靠部分: 字符串池一致前提下, 通过 field_ids 计数差定位"新增字段"(如毒字段/注入字段)。
注意: 若两个 dex 经过不同工具重建(method_ids/条目顺序会重排), 方法级对比请用 andro_diff.py。

用法:
    python dexdeep.py <old.dex> <new.dex>

依赖: 仅标准库
"""
import struct
import sys
from collections import Counter

FIELDS = ['file_size', 'header_size', 'endian_tag', 'link_size', 'link_off', 'map_off',
          'string_ids_size', 'string_ids_off', 'type_ids_size', 'type_ids_off',
          'proto_ids_size', 'proto_ids_off', 'field_ids_size', 'field_ids_off',
          'method_ids_size', 'method_ids_off', 'class_defs_size', 'class_defs_off',
          'data_size', 'data_off']


class Dex:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        b = self.data
        (self.file_size, self.header_size, self.endian_tag, self.link_size, self.link_off,
         self.map_off, self.string_ids_size, self.string_ids_off, self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off, self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off, self.class_defs_size, self.class_defs_off,
         self.data_size, self.data_off) = struct.unpack_from('<20I', b, 32)
        self.strs = []
        for i in range(self.string_ids_size):
            (so,) = struct.unpack_from('<I', b, self.string_ids_off + i * 4)
            p = so
            while b[p] & 0x80:
                p += 1
            p += 1
            end = b.index(b'\x00', p)
            self.strs.append(b[p:end].decode('utf-8', 'replace'))

    def type_desc(self, idx):
        (si,) = struct.unpack_from('<I', self.data, self.type_ids_off + idx * 4)
        return self.strs[si]

    def fields(self):
        out = []
        for i in range(self.field_ids_size):
            c, t, n = struct.unpack_from('<HHI', self.data, self.field_ids_off + i * 8)
            out.append((c, t, n))
        return out

    def class_defs(self):
        out = []
        for i in range(self.class_defs_size):
            raw = struct.unpack_from('<8I', self.data, self.class_defs_off + i * 32)
            out.append(dict(class_idx=raw[0], class_data_off=raw[6], static_values=raw[7],
                            annotations_off=raw[5]))
        return out


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    a, b = Dex(sys.argv[1]), Dex(sys.argv[2])

    print('== 头部段数量对比')
    for k in FIELDS:
        va, vb = getattr(a, k), getattr(b, k)
        if va != vb:
            print(f'   {k}: {va} -> {vb} (delta {vb - va})')

    print('\n== field_ids 增删(按 类/字段类型 计数, 与重排无关)')
    fa, fb = a.fields(), b.fields()
    ca = Counter((x[0], x[1]) for x in fa)
    cb = Counter((x[0], x[1]) for x in fb)
    changed = 0
    for key in set(ca) | set(cb):
        if ca.get(key, 0) == cb.get(key, 0):
            continue
        changed += 1
        cls, ftype = a.type_desc(key[0]), a.type_desc(key[1])
        names_a = {x[2] for x in fa if (x[0], x[1]) == key}
        names_b = {x[2] for x in fb if (x[0], x[1]) == key}
        print(f'   class: {cls}  字段类型: {ftype}  ({ca.get(key, 0)} -> {cb.get(key, 0)})')
        for n in sorted(names_b - names_a):
            print(f'      + 字段: {a.strs[n]}')
        for n in sorted(names_a - names_b):
            print(f'      - 字段: {a.strs[n]}')
    if not changed:
        print('   (无 field_ids 差异)')

    print('\n== class_data 中的字段数变化 / static_values / annotations 偏移')
    cda, cdb = a.class_defs(), b.class_defs()
    for da, db in zip(cda, cdb):
        cls = a.type_desc(da['class_idx'])
        if da['static_values'] != db['static_values']:
            print(f'   static_values 变化: {cls} {da["static_values"]:#x} -> {db["static_values"]:#x}')
        if da['annotations_off'] != db['annotations_off']:
            print(f'   annotations 偏移变化: {cls} {da["annotations_off"]:#x} -> {db["annotations_off"]:#x}')


if __name__ == '__main__':
    main()
