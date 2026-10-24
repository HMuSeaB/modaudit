# androguard 版字段级 diff: 按类对比字段名集合(权威, 无跨表索引问题)
import sys
from loguru import logger
logger.remove()
from androguard.core.dex import DEX

def field_map(path):
    d = DEX(open(path, 'rb').read())
    out = {}
    for c in d.get_classes():
        cn = c.get_name()
        for f in c.get_fields():
            out.setdefault(cn, set()).add((f.get_name(), f.get_descriptor()))
    return out

a = field_map(sys.argv[1])
b = field_map(sys.argv[2])
added = removed = 0
for cls in sorted(set(a) | set(b)):
    fa = a.get(cls, set())
    fb = b.get(cls, set())
    if fa == fb:
        continue
    plus = fb - fa
    minus = fa - fb
    if not plus and not minus:
        continue
    if cls not in a: print(f"== 仅B有类: {cls} ({len(fb)} 字段)"); added += len(fb); continue
    if cls not in b: print(f"== 仅A有类: {cls} ({len(fa)} 字段)"); removed += len(fa); continue
    print(f"== {cls}: +{len(plus)} -{len(minus)}")
    for n, d in sorted(plus)[:10]: print(f"   + {d} {n}")
    for n, d in sorted(minus)[:10]: print(f"   - {d} {n}")
    added += len(plus); removed += len(minus)
print(f"\n汇总: 新增字段={added} 删除字段={removed}")
