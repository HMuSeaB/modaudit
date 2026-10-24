# 零底包毒字段/毒方法探测器: 扫描 dex 中不是合法 Java 标识符的字段名/方法名
# 原理: Java/Kotlin 源码编译出的名字只能是 [A-Za-z_$][A-Za-z0-9_$]*,
#       含空格/%/标点的名字必然来自 smali/dex 手术(如 "extras is null"、"%s" 结尾的日志句)
# 用法: python poison_scan.py <apk|apks> [--min-len 6]
import sys, re, zipfile, io, os
from loguru import logger
logger.remove()
from androguard.core.dex import DEX

VALID = re.compile(r'^[A-Za-z_$][A-Za-z0-9_$]*$')
SPECIAL_METHODS = {'<init>', '<clinit>'}
# Kotlin 编译器合法产物(白名单): -impl / $lambda-N / $default / access$ / $annotations
KOTLIN_OK = re.compile(r'^[A-Za-z0-9_$]+(-[a-z]+(-impl0?)?|(\$lambda-\d+)|(\$default)|(\$annotations))?$')

def suspicious(n):
    """含空格/百分号/方括号/圆点等不可能出现在编译器产物中的字符"""
    return not VALID.match(n) and not KOTLIN_OK.match(n)

def dex_files(target, depth=0):
    if depth == 0 and target.endswith('.apk'):
        z = zipfile.ZipFile(target)
        for n in z.namelist():
            if n.startswith('classes') and n.endswith('.dex'):
                yield (f'{os.path.basename(target)}:{n}', z.read(n))
        return
    z = zipfile.ZipFile(target)
    for n in z.namelist():
        if n.endswith('.apk') and not n.endswith('.apks'):
            inner = zipfile.ZipFile(io.BytesIO(z.read(n)))
            for m in inner.namelist():
                if m.startswith('classes') and m.endswith('.dex'):
                    yield (f'{os.path.basename(target)}::{m}', inner.read(m))
        elif n.endswith('.apks') and depth < 2:
            outer = zipfile.ZipFile(io.BytesIO(z.read(n)))
            for m in outer.namelist():
                if m.endswith('.apk'):
                    inner2 = zipfile.ZipFile(io.BytesIO(outer.read(m)))
                    for k in inner2.namelist():
                        if k.startswith('classes') and k.endswith('.dex'):
                            yield (f'{os.path.basename(target)}::{n}::{m}:{k}', inner2.read(k))

def main():
    target = sys.argv[1]
    for label, raw in dex_files(target):
        d = DEX(raw)
        bad_fields, bad_methods = [], []
        for c in d.get_classes():
            cn = c.get_name()
            for f in c.get_fields():
                n = f.get_name()
                # 热补丁框架(InstantRun/ChangeQuickRedirect 等)的标记字段是合法产物, 白名单
                if f.get_descriptor().endswith('ChangeQuickRedirect;'):
                    continue
                if suspicious(n):
                    bad_fields.append((cn, n, f.get_descriptor()))
            for m in c.get_methods():
                n = m.get_name()
                if n in SPECIAL_METHODS: continue
                if suspicious(n):
                    bad_methods.append((cn, n, m.get_descriptor()))
        if bad_fields or bad_methods:
            print(f"== {label}: 非法标识符字段 {len(bad_fields)} / 方法 {len(bad_methods)}")
            for cn, n, fd in bad_fields[:20]:
                print(f"   [F] {cn} -> {n!r} : {fd}")
            for cn, n, fd in bad_methods[:10]:
                print(f"   [M] {cn} -> {n!r} {fd}")
        else:
            print(f"== {label}: 干净")

if __name__ == '__main__':
    main()
