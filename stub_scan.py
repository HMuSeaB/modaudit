#!/usr/bin/env python3
"""扫描 APK / .apks / zip 中被"掏空"的原生库桩与重建时间戳指纹。

两个信号:
1. stub .so —— 解压后极小的 .so(默认 < 4096B)。典型是 5 字节 ELF 头桩(\\x7fELF\\x02 截断):
   修改者用它替换广告 SDK/游戏引擎/安全组件等重型库, dlopen 必然失败但 App 有容错,
   于是库不加载、内存大降, 而加载逻辑不因缺文件而崩。
2. 时间戳指纹 —— MT管理器类工具重打包时把条目时间戳统一成固定值(如 1981-01-01 01:01),
   而被替换/注入的文件(桩、注入 dex、SignatureKiller 资产)保留修改当日的真实时间戳。
   统计每个容器的时间戳众数, 离群条目往往就是"被动过手脚的文件"。

用法:
    python stub_scan.py <apk|apks|zip>... [--threshold 4096]

依赖: 仅标准库。支持嵌套(zip 里套 apk/apks 自动下钻, 最深 2 层)。
"""
import argparse
import io
import zipfile
from collections import Counter

ELF_MAGIC = b'\x7fELF'


def describe_so(data, size):
    if size >= 64 and data[:4] == ELF_MAGIC:
        kind = 'elf'
    elif 0 < size < 64:
        kind = f'stub(data={data[:8].hex()})'
    else:
        kind = 'tiny'
    return kind


def scan_container(zf, label, threshold, depth):
    stubs = []
    for info in zf.infolist():
        name = info.filename
        if name.endswith('/'):
            continue
        if name.endswith('.so') and info.file_size < threshold:
            data = zf.read(name)
            stubs.append((name, info.file_size, info.date_time, describe_so(data, len(data))))
        elif depth < 2 and name.endswith(('.apk', '.apks')):
            try:
                inner = zipfile.ZipFile(io.BytesIO(zf.read(name)))
            except zipfile.BadZipFile:
                continue
            print(f'--- 下钻 {label} :: {name}')
            scan_container(inner, f'{label}::{name}', threshold, depth + 1)
    if stubs:
        print(f'== {label}: stub .so x{len(stubs)}')
        for name, size, ts, kind in stubs:
            print(f'   {size:7d}B  {ts}  {name}   [{kind}]')
    else:
        print(f'== {label}: 无 stub .so')

    ts_counter = Counter()
    ts_of = {}
    for i in zf.infolist():
        if not i.filename.endswith('/'):
            ts_counter[i.date_time] += 1
            ts_of[i.filename] = i.date_time
    if ts_counter:
        modal_ts, modal_n = ts_counter.most_common(1)[0]
        total = sum(ts_counter.values())
        outliers = [(n, t) for n, t in ts_of.items() if t != modal_ts]
        print(f'   时间戳众数 {modal_ts} 占 {modal_n}/{total}'
              f'{" (高度一致, 疑似重打包)" if modal_n / total > 0.95 else ""}'
              f'  离群 {len(outliers)} 个')
        for n, t in sorted(outliers, key=lambda x: x[1])[:8]:
            print(f'     离群: {t}  {n}')


def main():
    ap = argparse.ArgumentParser(description='扫描掏空的 .so 桩 + 重建时间戳指纹')
    ap.add_argument('paths', nargs='+', help='apk / .apks / zip, 可多个')
    ap.add_argument('--threshold', type=int, default=4096, help='.so 判定为桩的大小上限(字节)')
    args = ap.parse_args()

    for path in args.paths:
        print('=' * 72)
        print('#', path)
        zf = zipfile.ZipFile(path)
        scan_container(zf, path, args.threshold, 0)


if __name__ == '__main__':
    main()
