# APK v2 签名块自校验: 判断包内容是否与签名块中记录的摘要一致(纯标准库实现)
# 原理: v2 签名块记录官方构建时对文件三段(签名块前/签名块后/中央目录至尾)的 1MB 分块摘要。
#       "保留原签名块"式修改(Root 路线)改了内容但签名块原样 → 重算摘要与记录不符 → 必然检出。
#       正常官方包 → 完全一致; 正确重签的包 → 也一致(但证书非原厂, 需另查证书指纹)。
# 用法: python verify_v2.py <apk>   输出: 每个 signer 的摘要一致性
import struct, sys, hashlib, io, zipfile

CHUNK = 1048576
CONTENT_DIGESTS = {1: ('sha1', b'\x5a'), 2: ('sha256', b'\xa5'), 3: ('sha512', b'\xbc')}
SIGALGO_DIGEST = {0x0101:2, 0x0102:3, 0x0103:2, 0x0104:3, 0x0421:2, 0x0423:2, 0x0201:2, 0x0202:3, 0x0301:2, 0x0441:2}


def u32(b, p): return struct.unpack_from('<I', b, p)[0]
def u64(b, p): return struct.unpack_from('<Q', b, p)[0]


def find_signing_block(data):
    """返回 (block_start, pairs_start, pairs_end, cd_off) 或 None"""
    eocd = data.rfind(b'PK\x05\x06')
    if eocd < 0: return None
    cd_off = u32(data, eocd + 16)
    if cd_off == 0xFFFFFFFF:
        return None  # zip64 暂不支持
    if cd_off < 32: return None
    if data[cd_off-16:cd_off] != b'APK Sig Block 42':
        return None
    block_size = u64(data, cd_off - 24)      # size 值 = 除自身 8 字节外的块长
    block_start = cd_off - 8 - block_size    # 块 = [size1][pairs][size2][magic]
    if block_start < 0: return None
    return block_start, block_start + 8, cd_off - 24, cd_off


def iter_pairs(data, start, end):
    p = start
    while p + 12 <= end:
        plen = u64(data, p)
        pid = u32(data, p + 8)
        val = data[p+12:p+8+plen]
        yield pid, val, p, plen
        p += 8 + plen


def lp(data, p):
    """length-prefixed bytes: 返回 (内容, 新位置)"""
    n = u32(data, p)
    return data[p+4:p+4+n], p+4+n


def compute_digests(data, sections, content_digest_id):
    algo, prefix = CONTENT_DIGESTS[content_digest_id]
    h = hashlib.new(algo)
    chunk_digests = []
    for s_start, s_end in sections:
        pos = s_start
        while pos < s_end:
            chunk = data[pos:min(pos+CHUNK, s_end)]
            chunk_digests.append(hashlib.new(algo, prefix + chunk).digest())
            pos += CHUNK
    h.update(b''.join(chunk_digests))
    return h.digest()


def verify(path):
    data = open(path, 'rb').read()
    sb = find_signing_block(data)
    if sb is None:
        return dict(status='no-v2-block', signers=[])
    block_start, pairs_start, pairs_end, cd_off = sb
    sb_end = cd_off - 24
    eocd_off = data.rfind(b'PK')
    sections = [(0, block_start), (cd_off, eocd_off), (eocd_off, len(data))]  # AOSP 三段: 块前 / 中央目录 / EOCD
    results = []
    for pid, val, _, _ in iter_pairs(data, pairs_start, pairs_end):
        if pid not in (0x7109871a, 0xf05368c0):  # v2 / v3
            continue
        scheme = 'v2' if pid == 0x7109871a else 'v3'
        # signers: LP of LP(signer)
        signers_blob, p = lp(val, 0)
        q = 0
        si = 0
        while q + 4 <= len(signers_blob):
            signer, q = lp(signers_blob, q)
            si += 1
            # signer = LP(signed data) + LP(signatures) + LP(public key)
            signed_data, p2 = lp(signer, 0)
            sigs_blob, _ = lp(signer, p2)
            pubkey, _ = lp(signer, p2 + 4 + u32(signer, p2))
            # signed data = LP(digests) + LP(certs) + LP(attributes)
            digests_blob, p3 = lp(signed_data, 0)
            # digests = sequence of LP( u32 algo + digest )
            rec = []
            pp = 0
            end = len(digests_blob)
            while pp + 8 <= end:
                dlen = u32(digests_blob, pp)
                algo = u32(digests_blob, pp+4)
                dval = digests_blob[pp+12:pp+4+dlen]
                rec.append((algo, dval))
                pp += 4 + dlen
            # 逐算法重算并比对
            signer_ok = True
            detail = []
            for algo, recorded in rec:
                cd_id = SIGALGO_DIGEST.get(algo)
                if cd_id is None:
                    detail.append((f'algo {algo:#x}', '?', '未知签名算法')); signer_ok = False; continue
                expected = compute_digests(data, sections, cd_id)
                ok = expected == recorded
                detail.append((f'algo {algo:#x}', recorded.hex()[:16], '一致' if ok else '不一致'))
                if not ok: signer_ok = False
            results.append(dict(scheme=scheme, signer_index=si,
                                certs=len(re.findall(b'-----', b'')) if False else None,
                                ok=signer_ok, detail=detail))
    return dict(status='ok', signers=results)


def main():
    path = sys.argv[1]
    r = verify(path)
    if r['status'] != 'ok':
        print(f"{path}: {r['status']}")
        return
    verdict = '全部一致' if all(s['ok'] for s in r['signers']) else '存在不一致 → **内容与签名块不符(已修改)**'
    print(f"{path}: v2/v3 签名块 {len(r['signers'])} 个 signer, {verdict}")
    for s in r['signers']:
        print(f"  [{s['scheme']} signer#{s['signer_index']}] {'一致' if s['ok'] else '不一致'}")
        for d in s['detail']:
            print(f"     {d[0]}: {d[1]} {d[2]}")


if __name__ == '__main__':
    main()
