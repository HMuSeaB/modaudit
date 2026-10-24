#!/usr/bin/env python3
"""修改版 APK 一键审计流水线 —— 把整个研究方法论固化成一条命令。

对任意"修改版"安装包自动执行:
  1. 签名路线判定     (原厂证书保留=Root路线 / 重签+SignatureKiller=免Root路线)
  2. 时间戳指纹       (找出被单独替换的文件)
  3. v1 摘要校验      (有 v1 时精确枚举 被修改/被删除 文件)
  4. 掏空 .so 桩扫描
  5. 毒字段探测       (非法标识符字段名 = smali 注入痕迹)
  6. manifest 结构    (组件/进程/被删服务)
  7. 官方底包对比     (--official 提供同构建底包时: 文件 CRC diff, --deep 加方法级)
  8. 汇总生成 结论.md

用法:
    python modaudit.py <修改版.apk|.apks|.zip> [--official 官方包] [--out 输出目录]
    python modaudit.py 抖音.apk --official official/抖音官方.apks --deep

依赖: 本目录其他脚本; androguard(部分步骤)。所有中间产物保存在输出目录, 可复跑。
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def run(script, args, out_file=None):
    cmd = [PY, os.path.join(HERE, script)] + args
    r = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    text = (r.stdout or '') + (('\n[stderr]\n' + r.stderr) if r.stderr.strip() else '')
    if out_file:
        open(out_file, 'w', encoding='utf-8').write(text)
    return text


def step(title, text):
    print(f"\n### {title}\n{text.strip()[:400]}", file=sys.stderr)


# ---------- 各步骤结果解析 ----------

def parse_apk_metadata(text):
    info = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        k, _, v = line.strip().partition(':')
        k = k.strip()
        if k == 'package':
            parts = v.split()
            info['package'] = parts[0] if parts else ''
            for p in parts[1:]:
                if p.startswith('versionName:'):
                    info['version'] = p.split(':', 1)[1]
        elif k == '签名方案':
            m = re.search(r'v1=(\w+) v2=(\w+) v3=(\w+)', v)
            if m:
                info['v1'], info['v2'], info['v3'] = m.group(1) == 'True', m.group(2) == 'True', m.group(3) == 'True'
        elif k == '证书 subject':
            info['cert'] = v.strip()
        elif k == '解压总大小':
            info['size'] = v.strip()
    return info


def parse_stub_scan(text):
    stubs, outliers, mode = [], [], None
    for line in text.splitlines():
        if '.so' in line and re.match(r'\s+\d+\s*B\s', line):
            stubs.append(line.strip())
        m = re.search(r'时间戳众数 \(([^)]*)\) 占 (\d+)/(\d+)', line)
        if m:
            ratio = int(m.group(2)) / max(1, int(m.group(3)))
            mode = (m.group(1), f"{ratio:.0%}")
        if '离群:' in line:
            outliers.append(line.split('离群:')[1].strip())
    return stubs, outliers, mode


def parse_v1(text):
    modified, deleted = [], []
    in_sec = None
    for line in text.splitlines():
        if line.startswith('MODIFIED') or '被修改' in line:
            in_sec = 'mod'
        elif line.startswith('MISSING') or line.startswith('删除') or '缺失' in line:
            in_sec = 'del'
        elif re.match(r'^\s+[*-] ', line):
            name = re.sub(r'^\s+[*-] (\[[^\]]+\] )?', '', line).strip()
            (modified if in_sec == 'mod' else deleted).append(name)
        elif line.startswith('同键') or line.startswith('=='):
            in_sec = None
    return modified, deleted


def parse_poison(text):
    fields = []
    for line in text.splitlines():
        if line.strip().startswith('[F]'):
            fields.append(line.split('[F]')[1].strip())
    return fields


def parse_signature_killer(files):
    marks = [f for f in files if 'SignatureKiller' in f or 'KillerApplication' in f or f.startswith('bin/mt/')]
    return marks


# ---------- 主流程 ----------

def main():
    ap = argparse.ArgumentParser(description='修改版 APK 一键审计')
    ap.add_argument('target')
    ap.add_argument('--official', help='同构建官方底包(apk/apks/xapk/apkm), 提供后做 CRC diff')
    ap.add_argument('--deep', action='store_true', help='官方对比时追加方法级 dex diff(慢)')
    ap.add_argument('--out', default='audit_report')
    ap.add_argument('--auto-baseline', action='store_true',
                    help='无 --official 时自动尝试 apkpure 下载同版本官方包')
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    report = []  # (section_title, text)

    def sec(title, text):
        report.append((title, text))

    print('== [1/7] 包元信息与签名路线', file=sys.stderr)
    meta_txt = run('analyze_apk.py', [args.target])
    open(os.path.join(out, '1_元信息.txt'), 'w', encoding='utf-8').write(meta_txt)
    meta = parse_apk_metadata(meta_txt)
    pkg = meta.get('package', 'unknown')
    ver = meta.get('version', '')
    print(f'   {pkg} {ver}  证书: {meta.get("cert", "?")[:60]}', file=sys.stderr)

    print('== [2/7] 时间戳指纹 + .so 桩', file=sys.stderr)
    stub_txt = run('stub_scan.py', [args.target])
    open(os.path.join(out, '2_时间戳与桩.txt'), 'w', encoding='utf-8').write(stub_txt)
    stubs, outliers, mode = parse_stub_scan(stub_txt)

    print('== [3/7] v1 摘要校验(若有)', file=sys.stderr)
    v1_txt = ''
    v1_mod, v1_del = [], []
    if meta.get('v1'):
        inner_apk = None
        z = zipfile.ZipFile(args.target)
        apks = [n for n in z.namelist() if n.endswith('.apk') and not n.endswith('.apks')]
        if args.target.endswith('.apk'):
            v1_txt = run('verify_v1.py', [args.target])
        elif apks:
            cand = [n for n in apks if os.path.basename(n).startswith('base')] or apks
            data = z.read(cand[0])
            t = tempfile.NamedTemporaryFile(suffix='.apk', delete=False)
            t.write(data); t.close()
            v1_txt = run('verify_v1.py', [t.name])
            os.unlink(t.name)
        else:
            v1_txt = run('verify_v1_full.py', [args.target])
    else:
        v1_txt = '(无 v1 签名, 跳过 —— Root 路线包普遍如此)'
    open(os.path.join(out, '3_v1校验.txt'), 'w', encoding='utf-8').write(v1_txt)
    if '全匹配' in v1_txt or ('mismatch=0' in v1_txt and '一致' in v1_txt) or '值差异=0' in v1_txt:
        pass
    v1_mod, v1_del = parse_v1(v1_txt)

    print('== [4/7] 毒字段探测', file=sys.stderr)
    poison_txt = run('poison_scan.py', [args.target])
    open(os.path.join(out, '4_毒字段.txt'), 'w', encoding='utf-8').write(poison_txt)
    poison = parse_poison(poison_txt)

    print('== [5/7] manifest 结构', file=sys.stderr)
    man_txt = run('manifest_dump.py', [args.target])
    open(os.path.join(out, '5_manifest.txt'), 'w', encoding='utf-8').write(man_txt)

    diff_txt = ''
    if args.official:
        print('== [6/7] 官方底包对比', file=sys.stderr)
        diff_args = [args.target, '--files']
        if args.deep:
            diff_args.append('--methods')
        diff_txt = run('apk_diff.py', [args.official] + diff_args)
        open(os.path.join(out, '6_官方对比.txt'), 'w', encoding='utf-8').write(diff_txt)
    elif args.auto_baseline and pkg != 'unknown' and ver:
        print('== [6/7] 自动获取官方底包(apkpure)', file=sys.stderr)
        r = subprocess.run([PY, os.path.join(HERE, 'apkpure_dl.py'), f'{pkg}:{ver}',
                            '--out', os.path.join(out, 'baseline')],
                           capture_output=True, text=True)
        got = [f for f in os.listdir(os.path.join(out, 'baseline'))] if os.path.isdir(os.path.join(out, 'baseline')) else []
        if got:
            bf = os.path.join(out, 'baseline', got[0])
            diff_txt = run('apk_diff.py', [bf, args.target, '--files'])
            open(os.path.join(out, '6_官方对比.txt'), 'w', encoding='utf-8').write(diff_txt)
        else:
            diff_txt = '(apkpure 无此版本: ' + (r.stdout[-200:] + r.stderr[-200:] if r.stdout or r.stderr else '') + ')'
            open(os.path.join(out, '6_官方对比.txt'), 'w', encoding='utf-8').write(diff_txt)
    else:
        open(os.path.join(out, '6_官方对比.txt'), 'w', encoding='utf-8').write('(未提供官方底包, 跳过对比)')

    # ---------- 汇总 ----------
    print('== [7/7] 生成结论', file=sys.stderr)
    killer = parse_signature_killer([])  # 从文件名集合判: 用 zip 全表扫一遍
    allnames = []
    try:
        z = zipfile.ZipFile(args.target)
        allnames = z.namelist()
        for n in list(allnames):
            if n.endswith(('.apk', '.apks')):
                try:
                    zi = zipfile.ZipFile(io.BytesIO(z.read(n))) if n != args.target else z
                    allnames += [f'{n}::{m}' for m in zi.namelist()]
                except Exception:
                    pass
    except Exception:
        pass
    killer = [f for f in allnames if 'SignatureKiller' in f or 'KillerApplication' in f or f.startswith('bin/mt/')]

    route = []
    if meta.get('v1'):
        if v1_mod:
            route.append('**Root 路线**(保留原签名块, 内容已改, 安装需 Root 签名校验绕过)。'
                         f'v1 摘要不匹配 {len(v1_mod)} 个文件 = 实际修改清单(构建精确)。')
        elif '全匹配' in v1_txt or 'mismatch=0' in v1_txt:
            route.append('v1 摘要全匹配 → **该包为官方原版, 未修改**。')
    else:
        if killer:
            route.append('**免 Root 路线**(重签 + MT KillerApplication 签名伪装): '
                         f'检出 SignatureKiller 痕迹 {len(killer)} 处。可全新安装, 签名非原厂。')
        else:
            route.append('无 v1 签名且无 SignatureKiller 痕迹 → 原厂证书保留的 v2/v3 包(可能为官方包或 Root 路线修改版), '
                         '需官方底包对比判定。')
    if mode and mode[1] in ('100%',) or (mode and mode[1].rstrip('%').isdigit() and int(mode[1].rstrip('%')) >= 95):
        route.append(f'时间戳众数 {mode[0]} 占 {mode[1]} → **确认重打包**(MT管理器系工具)。')

    touched = sorted(set(outliers) | set(v1_mod))
    sec('一、签名与打包路线', '\n'.join(f'- {r}' for r in route) if route else '(无)')
    sec('二、被单独替换/修改的文件(时间戳离群 ∪ v1不匹配)',
        '\n'.join(f'- {t}' for t in touched) or '- 无')
    if v1_del:
        sec('三、被删除的文件(v1 摘要枚举, 构建精确)',
            '\n'.join(f'- {t}' for t in v1_del[:200]) + (f'\n- …共 {len(v1_del)} 个' if len(v1_del) > 200 else ''))
    if stubs:
        sec('四、掏空 .so 桩', '\n'.join(f'- {s}' for s in stubs) +
            '\n⚠️ 注意: 大厂原生小桩(SDK动态化)与修改者桩的判别需官方底包比对, 见 01-总结.md')
    if poison:
        sec('五、疑似注入字段(非法标识符=smali 手术痕迹)', '\n'.join(f'- {p}' for p in poison[:40]))
    if diff_txt:
        sec('六、官方底包对比摘要', diff_txt.strip()[:3000] + ('\n…(完整见 6_官方对比.txt)' if len(diff_txt) > 3000 else ''))

    # 写结论
    md = [f'# 修改版审计报告 —— {os.path.basename(args.target)}',
          f'- 包名: {pkg}  版本: {ver}  解压大小: {meta.get("size","?")}',
          f'- 证书: {meta.get("cert","?")}',
          f'- 签名方案: v1={meta.get("v1")} v2={meta.get("v2")} v3={meta.get("v3")}', '']
    for title, text in report:
        md.append(f'## {title}\n{text}\n')
    md.append('## 附: 中间产物')
    for f in sorted(os.listdir(out)):
        if f.endswith(('.txt',)):
            md.append(f'- `{f}`')
    md_path = os.path.join(out, '结论.md')
    open(md_path, 'w', encoding='utf-8').write('\n'.join(md))
    print(f'== 完成: {md_path}', file=sys.stderr)


if __name__ == '__main__':
    main()
