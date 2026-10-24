#!/usr/bin/env python3
"""官方包 vs 修改包 的全量对比: 文件清单 diff(zip CRC, 免解压) + 跨 dex 方法级语义 diff。

用法:
    python apk_diff.py <official.apk> <modded.apk|.apks> --files     # 文件级: 删了什么/加了什么/改了什么
    python apk_diff.py <official.apk> <modded.apk|.apks> --methods   # 方法级: dex 代码真实改动
    python apk_diff.py official modded --files --methods --out r.txt

说明:
- .apks 会被当作 split 集合取全部内层 apk 的并集(与官方单包对齐)。
- --files 用 ZipInfo.CRC 判定内容是否变化, 不解压, 秒级。
- --methods 用 androguard 仅解析 dex 结构(不建交叉引用索引), 按 (类名,方法名,描述) 对齐后
  比较指令哈希 —— 免疫 dex 重建时的条目重排/偏移变化。大包需要几分钟到几十分钟。
- 版本号不一致的两侧会引入版本漂移噪音, 尽量用同 versionCode 的底包。

依赖: --files 纯标准库; --methods 需 androguard + loguru。
"""
import argparse
import hashlib
import io
import os
import sys
import tempfile
import zipfile

METHOD_OPS_SKIP = ()  # 占位: 保持接口一致


def iter_inner_apks(target, depth=0):
    """apk -> [自身]; .apks/.zip -> 内层 apk 流列表(惰性解包到内存); zip 套 apks 自动下钻"""
    if depth == 0 and target.endswith('.apk'):
        yield target
        return
    z = zipfile.ZipFile(target)
    inners = [n for n in z.namelist() if n.endswith('.apk') and not n.endswith('.apks')]
    if not inners:
        for n in z.namelist():
            if n.endswith(('.apks', '.zip')):
                yield from iter_inner_apks_bytes(z.read(n), f'{os.path.basename(target)}::{n}', depth + 1)
        return
    for n in inners:
        yield (n, io.BytesIO(z.read(n)))


def iter_inner_apks_bytes(data, label, depth):
    z = zipfile.ZipFile(io.BytesIO(data))
    for n in z.namelist():
        if n.endswith('.apk') and not n.endswith('.apks'):
            yield (n, io.BytesIO(z.read(n)))
        elif depth < 2 and n.endswith(('.apks', '.zip')):
            yield from iter_inner_apks_bytes(z.read(n), f'{label}::{n}', depth + 1)


def collect_files(target):
    """-> {name: crc}。多 split 取并集(同名以先出现者为准, split 间内容本就互斥)。"""
    files = {}
    for item in iter_inner_apks(target):
        if isinstance(item, str):
            z = zipfile.ZipFile(item)
        else:
            z = zipfile.ZipFile(item[1])
        for i in z.infolist():
            if not i.filename.endswith('/'):
                files.setdefault(i.filename, i.CRC)
    return files


def file_diff(official, modded):
    fa, fb = collect_files(official), collect_files(modded)
    deleted = sorted(set(fa) - set(fb))
    added = sorted(set(fb) - set(fa))
    modified = sorted(n for n in (set(fa) & set(fb)) if fa[n] != fb[n])
    same = len(fa) - len(deleted) - len(modified)
    print(f"[files] 官方条目={len(fa)} 修改版条目={len(fb)}  两侧一致={same}")
    for title, names in (('仅官方有(被删除)', deleted), ('仅修改版有(新增)', added), ('内容被修改', modified)):
        print(f"  {title}: {len(names)} 个")
        for n in names[:80]:
            print(f"    {n}")
        if len(names) > 80:
            print(f"    ... 其余 {len(names) - 80} 个略")
    return deleted, added, modified


def dex_files(target):
    """-> [(dex名, 原始字节)], 从 apk 或 .apks 中取全部 dex。"""
    out = []
    for item in iter_inner_apks(target):
        if isinstance(item, str):
            z = zipfile.ZipFile(item)
            label = os.path.basename(item)
        else:
            z = zipfile.ZipFile(item[1])
            label = os.path.basename(item[0])
        for n in z.namelist():
            if n.startswith('classes') and n.endswith('.dex'):
                out.append((f'{label}:{n}', z.read(n)))
    return out


def method_map(target):
    from loguru import logger
    logger.remove()
    from androguard.core.dex import DEX
    result = {}
    dexes = dex_files(target)
    for i, (label, raw) in enumerate(dexes):
        print(f'  [methods] 解析 {label} ({i + 1}/{len(dexes)})', file=sys.stderr)
        d = DEX(raw)
        for m in d.get_methods():
            key = (m.get_class_name(), m.get_name(), m.get_descriptor())
            try:
                code = m.get_code()
                if code is None:
                    h = '<no-code>'
                else:
                    h = hashlib.md5(
                        '\n'.join(ins.get_output() for ins in m.get_instructions()).encode()
                    ).hexdigest()
            except Exception as e:
                h = f'<err {e}>'
            result.setdefault(key, set()).add(h)
    return result


def method_diff(official, modded):
    ma = method_map(official)
    mb = method_map(modded)
    ka, kb = set(ma), set(mb)
    changed, added, removed = [], sorted(kb - ka), sorted(ka - kb)
    for k in (ka & kb):
        if ma[k] != mb[k]:
            changed.append(k)
    print(f"[methods] 官方方法={len(ka)} 修改版方法={len(kb)}  变动={len(changed)} 新增={len(added)} 删除={len(removed)}")
    for title, names, mark in (('字节码变动', changed, '*'), ('新增方法', added, '+'), ('删除方法', removed, '-')):
        print(f"  {title}: {len(names)}")
        # 按类聚合展示
        from collections import Counter
        by_cls = Counter(k[0] for k in names)
        for cls, cnt in by_cls.most_common(40):
            print(f"    {mark} {cls}  ({cnt})")
            for k in [x for x in sorted(names) if x[0] == cls][:4]:
                print(f"        {mark} {k[1]}{k[2]}")
    return changed, added, removed


def main():
    ap = argparse.ArgumentParser(description='官方包 vs 修改包 全量对比')
    ap.add_argument('official')
    ap.add_argument('modded')
    ap.add_argument('--files', action='store_true', help='文件级对比(默认开启)')
    ap.add_argument('--methods', action='store_true', help='方法级 dex 对比')
    ap.add_argument('--out', help='结果同时写入该文件')
    args = ap.parse_args()
    if not args.files and not args.methods:
        args.files = True

    if args.out:
        sys.stdout = _Tee(sys.stdout, open(args.out, 'w', encoding='utf-8'))
    if args.files:
        file_diff(args.official, args.modded)
    if args.methods:
        method_diff(args.official, args.modded)


class _Tee:
    def __init__(self, a, b):
        self.a, self.b = a, b

    def write(self, s):
        self.a.write(s)
        self.b.write(s)

    def flush(self):
        self.a.flush()
        self.b.flush()


if __name__ == '__main__':
    main()
