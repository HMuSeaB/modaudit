#!/usr/bin/env python3
"""校验 APK 的 v1(JAR) 签名摘要是否与文件实际内容一致, 精确枚举"被修改/被删除"的文件。

原理: v1 签名的 META-INF/MANIFEST.MF 记录了包内每个文件的 SHA-1/SHA-256 摘要。
修改者若"保留原签名块重打包", 摘要仍是官方原版留下的, 于是:
  - 摘要全部匹配  -> 包内容未被修改(官方原版, 或被当作底包保留)
  - 摘要不匹配    -> 该文件被修改(5 个 dex、stub 的 .so 等)
  - 引用项缺失    -> 文件被删除; 若对象是 split 集合的 base.apk, 也可能是被移进了
                    split —— 请改用 verify_v1_full.py 区分

用法:
    python verify_v1.py <apk路径> [--samples N]

依赖: 仅标准库。适用前提: 目标 apk 含 v1 签名(is_signed_v1()=True), 可先用 analyze_apk.py 确认。
"""
import argparse
import base64
import hashlib
import zipfile


def unwrap(lines):
    """处理 JAR 规范的续行: 超过 72 字符的行会折行, 续行以单个空格开头。"""
    out = []
    for line in lines:
        if line.startswith(' ') and out:
            out[-1] += line[1:]
        else:
            out.append(line)
    return out


def parse_manifest(mf_text):
    """解析 MANIFEST.MF -> {文件名: (摘要b64, 算法)}。"""
    entries = {}
    cur = None
    for line in unwrap(mf_text.splitlines()):
        low = line.lower()
        if low.startswith('name:'):
            cur = line[5:].strip()
        elif low.startswith('sha-1-digest:') or low.startswith('sha-256-digest:'):
            if cur is not None:
                entries[cur] = (line.split(':', 1)[1].strip(), 'sha256' if '256' in low else 'sha1')
                cur = None
    return entries


def main():
    ap = argparse.ArgumentParser(description='v1 签名摘要校验: 枚举被修改/删除的文件')
    ap.add_argument('apk', help='apk 文件路径')
    ap.add_argument('--samples', type=int, default=15, help='每类最多打印的样例数 (默认 15)')
    args = ap.parse_args()

    z = zipfile.ZipFile(args.apk)
    names = set(z.namelist())
    try:
        mf = z.read('META-INF/MANIFEST.MF').decode('utf-8', 'replace')
    except KeyError:
        raise SystemExit('该包没有 META-INF/MANIFEST.MF (无 v1 签名), 无法做摘要校验。'
                         '可改用 analyze_apk.py / stub_scan.py 从其他角度分析。')

    entries = parse_manifest(mf)
    n_match = n_mod = n_miss = 0
    modified, deleted = [], []
    for name, (digest, algo) in entries.items():
        n = name[2:] if name.startswith('./') else name
        if n not in names:
            n_miss += 1
            deleted.append(n)
            continue
        h = hashlib.sha256() if algo == 'sha256' else hashlib.sha1()
        h.update(z.read(n))
        if base64.b64encode(h.digest()).decode() == digest:
            n_match += 1
        else:
            n_mod += 1
            modified.append(n)

    print(f"manifest 引用: {len(entries)}")
    print(f"一致={n_match}  被修改={n_mod}  缺失(删除或移入split)={n_miss}")
    if modified:
        print(f"MODIFIED ({n_mod}):")
        for n in modified[:args.samples]:
            print("   *", n)
    if deleted:
        print(f"MISSING ({n_miss}):")
        for n in deleted[:args.samples]:
            print("   -", n)


if __name__ == '__main__':
    main()
