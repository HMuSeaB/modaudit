#!/usr/bin/env python3
"""修改版 APK 审计面板 —— 本地 Web 界面。

功能:
  /            覆盖矩阵 + 审计任务列表 + 研究文件导航
  /audit       提交审计(任意 apk/apks/zip, 可选官方底包 / 自动拉底包 / 方法级深扫)
  /job/<id>    任务进度(实时)
  /report/<id> 渲染审计结论
  /view?path=  浏览研究目录下的 md/txt/json 文件

用法:
    python panel.py [--port 5015] [--root D:\\4rchive\\Code\\anti-ads]

说明: 仅监听 127.0.0.1; 审计流水线复用本目录 modaudit.py, 输出存 <root>/_apkresearch/audits/<任务名>/
"""
import argparse
import glob
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

DEFAULT_ROOT = os.path.dirname(HERE)          # anti-ads/
RESEARCH = os.path.join(DEFAULT_ROOT, '_apkresearch')
AUDITS = os.path.join(RESEARCH, 'audits')

JOBS = {}   # job_id -> dict(status, log, out_dir, started)


def run_audit_thread(job_id, target, official, deep, auto_baseline, out_dir):
    job = JOBS[job_id]
    job['status'] = 'running'
    args = [PY, os.path.join(HERE, 'modaudit.py'), target,
            '--out', out_dir]
    if official:
        args += ['--official', official]
    if deep:
        args.append('--deep')
    if auto_baseline:
        args.append('--auto-baseline')
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding='utf-8', errors='replace', cwd=HERE)
        job['proc'] = proc
        for line in proc.stdout:
            job['log'].append(line.rstrip())
        proc.wait()
        job['status'] = 'done' if proc.returncode == 0 else f'failed(exit {proc.returncode})'
    except Exception as e:
        job['log'].append(f'[panel error] {e}')
        job['status'] = 'failed'
    job['log'].append(f'[完成时间] {time.strftime("%H:%M:%S")}')


# ---------- 视图 ----------

from flask import Flask, request, redirect, Response

app = Flask(__name__)

CSS = """
body{font-family:"Microsoft YaHei",system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1c2733}
header{background:#1c2733;color:#fff;padding:14px 24px}
header h1{margin:0;font-size:18px} header .sub{opacity:.7;font-size:12px}
main{max-width:1100px;margin:20px auto;padding:0 16px}
.card{background:#fff;border-radius:10px;padding:18px 22px;margin-bottom:18px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #edf0f3}
th{color:#5b6b7c;font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px}
.ok{background:#e2f5e8;color:#177a3d}.warn{background:#fdf0dc;color:#9a6b0b}
.bad{background:#fde3e3;color:#a12626}.na{background:#eceff3;color:#5b6b7c}
input[type=text]{width:70%;padding:7px 10px;border:1px solid #cfd8e0;border-radius:6px;font-size:14px}
button{padding:8px 18px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-size:14px;cursor:pointer}
a{color:#2563eb;text-decoration:none} a:hover{text-decoration:underline}
pre{background:#0f1720;color:#d7e2ec;padding:12px;border-radius:8px;overflow:auto;font-size:12px;line-height:1.5}
.md h2{border-bottom:2px solid #e8ecf0;padding-bottom:4px}
.log{max-height:340px;overflow:auto;background:#0f1720;color:#9fe08f;padding:10px;border-radius:8px;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap}
"""


def page(title, body):
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title><style>{CSS}</style></head><body><header><h1>修改版 APK 审计面板</h1><div class='sub'>modaudit 流水线 · {html.escape(DEFAULT_ROOT)}</div></header><main>{body}</main></body></html>"


def md_to_html(text):
    """轻量 markdown 渲染(标题/表格/代码/列表/粗体)"""
    lines = html.escape(text).split('\n')
    out, in_code, in_table, in_list = [], False, False, False
    def close_table(): 
        if in_table: out.append('</table>')
    def close_list():
        if in_list: out.append('</ul>')
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('```'):
            close_table(); close_list()
            out.append('<pre>' if not in_code else '</pre>')
            in_code = not in_code
        elif in_code:
            out.append(line)
        elif line.startswith('| ') or line.startswith('|-'):
            cells = [c.strip() for c in line.strip('|').split('|')]
            if all(re.match(r'^:?-+:?$', c) for c in cells if c):
                i += 1; continue
            if not in_table:
                out.append('<table>'); in_table = True
                out.append('<tr>' + ''.join(f'<th>{c}</th>' for c in cells) + '</tr>')
            else:
                out.append('<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>')
        elif line.startswith('## '):
            close_table(); close_list()
            out.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('# '):
            close_table(); close_list()
            out.append(f'<h1>{line[2:]}</h1>')
        elif line.startswith('- '):
            if not in_list:
                close_table(); out.append('<ul>'); in_list = True
            content = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', line[2:])
            content = re.sub(r'`(.+?)`', r'<code>\1</code>', content)
            out.append(f'<li>{content}</li>')
        else:
            close_table(); close_list()
            if line.strip():
                content = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', line)
                content = re.sub(r'`(.+?)`', r'<code>\1</code>', content)
                out.append(f'<p>{content}</p>')
        i += 1
    close_table(); close_list()
    return '\n'.join(out)


def audit_list():
    audits = []
    if os.path.isdir(AUDITS):
        for name in sorted(os.listdir(AUDITS)):
            rp = os.path.join(AUDITS, name, '结论.md')
            if os.path.isfile(rp):
                audits.append(name)
    return audits


@app.route('/')
def index():
    rows = ''
    for name in audit_list():
        rows += f"<tr><td><a href='/report/{name}'>{html.escape(name)}</a></td><td><span class='badge ok'>已完成</span></td></tr>"
    body = f"""
<div class='card'><h2 style='margin-top:0'>审计任务</h2>
<table><tr><th>包</th><th>状态</th></tr>{rows or '<tr><td colspan=2>暂无 — 去提交一个</td></tr>'}</table>
<p><a href='/audit'>→ 提交新审计</a></p></div>

<div class='card'><h2 style='margin-top:0'>研究文件</h2><table>
<tr><th>文件</th></tr>"""
    for f in sorted(glob.glob(os.path.join(RESEARCH, '*.md'))):
        name = os.path.basename(f)
        body += f"<tr><td><a href='/view?path={html.escape(name)}'>{html.escape(name)}</a></td></tr>"
    body += "</table></div>"

    body += "<div class='card'><h2 style='margin-top:0'>官方底包(official/)</h2><table>"
    for f in sorted(glob.glob(os.path.join(RESEARCH, 'official', '*'))):
        sz = os.path.getsize(f) / 1048576
        body += f"<tr><td>{html.escape(os.path.basename(f))}</td><td style='text-align:right'>{sz:.0f} MB</td></tr>"
    body += "</table></div>"

    body += "<div class='card'><h2 style='margin-top:0'>证据文件(evidence/)</h2><p>"
    ev = sorted(os.listdir(os.path.join(RESEARCH, 'evidence'))) if os.path.isdir(os.path.join(RESEARCH, 'evidence')) else []
    body += ' '.join(f"<a href='/view?path=evidence/{html.escape(f)}'>{html.escape(f)}</a>" for f in ev[:40])
    body += f"</p><p>共 {len(ev)} 个文件 · <a href='/view?path=evidence/'>浏览全部</a></p></div>"
    return page('概览', body)


@app.route('/audit')
def audit_form():
    body = """
<div class='card'><h2 style='margin-top:0'>提交审计</h2>
<form action='/audit/start' method='post'>
<p>修改版路径 (apk/apks/zip):<br><input type=text name=target style='width:95%' placeholder='D:\\\\4rchive\\\\Code\\\\anti-ads\\\\精简软件\\\\xxx.apk'></p>
<p>官方底包路径 (可选, 同构建最佳):<br><input type=text name=official style='width:95%'></p>
<p><label><input type=checkbox name=deep value=1> 方法级 dex diff(慢, 需官方底包)</label>
&nbsp;&nbsp;<label><input type=checkbox name=auto_baseline value=1 checked> 无底包时自动尝试 apkpure 拉取</label></p>
<p>任务名 (可选):<input type=text name=name style='width:40%'></p>
<button type=submit>开始审计</button></form>
<p style='color:#5b6b7c;font-size:12px'>流水线: 签名路线 → 时间戳指纹 → v1 摘要 → .so 桩 → 毒字段 → manifest → 官方对比(可选)</p>
</div>"""
    return page('提交审计', body)


@app.route('/audit/start', methods=['POST'])
def audit_start():
    target = request.form.get('target', '').strip()
    official = request.form.get('official', '').strip()
    deep = bool(request.form.get('deep'))
    auto = bool(request.form.get('auto_baseline'))
    name = request.form.get('name', '').strip() or \
        re.sub(r'[^\w.-]', '_', os.path.basename(target)) or f'audit-{int(time.time())}'
    if not target or not os.path.exists(target):
        return page('错误', f"<div class='card'>修改版路径不存在: {html.escape(target)}<p><a href='/audit'>返回</a></p></div>")
    if official and not os.path.exists(official):
        return page('错误', f"<div class='card'>官方底包路径不存在: {html.escape(official)}<p><a href='/audit'>返回</a></p></div>")
    out_dir = os.path.join(AUDITS, name)
    job_id = uuid.uuid4().hex[:8]
    JOBS[job_id] = dict(status='queued', log=[], out_dir=out_dir, name=name)
    threading.Thread(target=run_audit_thread, args=(job_id, target, official, deep, auto, out_dir),
                     daemon=True).start()
    return redirect(f'/job/{job_id}')


@app.route('/job/<job_id>')
def job_view(job_id):
    job = JOBS.get(job_id)
    if not job:
        return page('错误', f"<div class='card'>任务不存在<p><a href='/'>返回</a></p></div>")
    log = html.escape('\n'.join(job['log'][-60:]))
    if job['status'] == 'done':
        meta = f"<p><a href='/report/{job['name']}'>→ 查看审计报告</a> · 输出目录: {html.escape(job['out_dir'])}</p>"
    elif job['status'].startswith('failed'):
        meta = f"<p style='color:#a12626'>任务失败, 见日志</p>"
    else:
        meta = f"<p>状态: {job['status']} — 页面每 2 秒自动刷新</p><meta http-equiv='refresh' content='2'>"
    body = f"<div class='card'><h2 style='margin-top:0'>任务 {html.escape(job['name'])}</h2>{meta}<div class='log'>{log}</div></div>"
    return page(f"任务 {job['name']}", body)


@app.route('/report/<name>')
def report(name):
    rp = os.path.join(AUDITS, name, '结论.md')
    if not os.path.isfile(rp):
        return page('错误', f"<div class='card'>报告不存在: {html.escape(name)}<p><a href='/'>返回</a></p></div>")
    text = open(rp, encoding='utf-8').read()
    # 附: 中间产物 变成链接
    text = re.sub(r'- `(\d_.+?\.txt)`', r"- <a href='/view?path=audits/{name}/\1'>\1</a>", text)
    body = f"<div class='card md'>{md_to_html(text)}</div><p><a href='/'>← 返回概览</a> · <a href='/view?path=audits/{html.escape(name)}/结论.md'>原始 markdown</a></p>"
    return page(f"审计报告 {name}", body)


@app.route('/view')
def view():
    rel = request.args.get('path', '')
    full = os.path.abspath(os.path.join(RESEARCH, rel))
    if not full.startswith(os.path.abspath(RESEARCH)):
        return page('错误', '<div class="card">路径越界</div>')
    if os.path.isdir(full):
        items = ''
        for f in sorted(os.listdir(full)):
            fp = os.path.join(full, f)
            relp = os.path.relpath(fp, RESEARCH).replace('\\', '/')
            items += f"<tr><td><a href='/view?path={html.escape(relp)}'>{html.escape(f)}</a></td><td style='text-align:right'>{os.path.getsize(fp) if os.path.isfile(fp) else '-'} B</td></tr>"
        return page(rel or '浏览', f"<div class='card'><table>{items}</table></div>")
    if not os.path.isfile(full):
        return page('错误', f"<div class='card'>文件不存在: {html.escape(rel)}</div>")
    text = open(full, encoding='utf-8', errors='replace').read()
    if full.endswith('.md'):
        body = f"<div class='card md'>{md_to_html(text)}</div>"
    else:
        body = f"<div class='card'><pre>{html.escape(text[:200000])}</pre></div>"
    return page(os.path.basename(full), body)


def main():
    global RESEARCH, AUDITS, DEFAULT_ROOT
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=5015)
    ap.add_argument('--root', default=DEFAULT_ROOT)
    args = ap.parse_args()
    DEFAULT_ROOT = args.root
    RESEARCH = os.path.join(args.root, '_apkresearch')
    AUDITS = os.path.join(RESEARCH, 'audits')
    os.makedirs(AUDITS, exist_ok=True)
    print(f'审计面板: http://127.0.0.1:{args.port}/  (Ctrl+C 退出)')
    app.run(host='127.0.0.1', port=args.port, debug=False)


if __name__ == '__main__':
    main()
