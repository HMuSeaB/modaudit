# apktools —— APK 精简版/修改版逆向工具箱

从 `精简软件/` 那批微信/QQ/抖音/夸克等修改版 APK 的逆向研究中沉淀出来的可复用脚本。
核心思路:**不依赖官方底包**(下载渠道通常被墙), 用包内自带的 v1 签名摘要、重打包指纹、
dex 结构特征做内证分析。

## 安装依赖

只有部分工具需要 androguard(签名/manifest/dex 反汇编);verify/stub/mapdiff 系列纯标准库。

```bash
python -m pip install -r requirements.txt
# 下载类工具(apkpure_dl/apkmirror_dl)如需代理:
#   set APKTOOL_PROXY=socks5h://127.0.0.1:7891   (Windows)  /  export APKTOOL_PROXY=...
```

## 工具一览

| 脚本 | 用途 | 依赖 |
|---|---|---|
| `analyze_apk.py` | 摸底: 包名/版本/**签名证书与方案**(判定 Root 路线还是重签路线)/文件构成/可疑文件名 | androguard |
| `verify_v1.py` | **单 apk v1 摘要校验**: 精确枚举"被修改/被删除"的文件 | 纯标准库 |
| `verify_v1_full.py` | 同上, 但 split 感知(.apks / 目录), 区分"移入 split"与"真删除" | 纯标准库 |
| `stub_scan.py` | 扫描被掏空的 5 字节 ELF 桩 .so + 重打包时间戳指纹(离群时间戳=被动过的文件) | 纯标准库 |
| `manifest_dump.py` | 组件/进程(:appbrand 之类)/enabled=false 导出 | androguard |
| `dexdiff.py` | 两 dex 快速对比: 头部段数量 + 字符串池增删(秒级) | 纯标准库 |
| `dexdeep.py` | 两 dex 结构对比: field_ids 增删(找毒字段) + static_values/annotations 变化 | 纯标准库 |
| `mapdiff.py` | 两 dex map_list 段字节量对比(定位 +N KB 在哪个段) | 纯标准库 |
| `andro_diff.py` | **方法级语义对比**(按类名/方法名对齐, 免疫重排噪音), 可选字段 xref | androguard |
| `xref_field.py` | 全 dex 扫描某字段的定义与读写点(判断孤儿字段/毒字段) | androguard |
| `poison_scan.py` | **零底包毒字段探测**: 扫字段/方法名中的非法标识符(空格/`%s` 等句文名即 smali 注入痕迹; Kotlin `-impl`/`$lambda-N` 需排除) | androguard |
| `encarray_diff.py` | dex static_values(encoded_array)语义级对比 | 纯标准库 |
| `apkpure_dl.py` | apkpure 历史版本下载器(apkeep 移植, 免账号免浏览器, 走 api.pureapk.com 内部 API) | 标准库+curl |
| `apkmirror_dl.py` | **apkmirror 静默下载器**(Playwright 驱动系统真 Chrome, 有头窗口移出屏幕外不可见; headless 会被该站 CF 硬拒; `expect_download` 静默落盘) | playwright |
| `apk_diff.py` | 官方底包 vs 修改包全量对比: 文件 CRC diff(秒级) + 跨 dex 方法级语义 diff | 标准库/androguard |
| `modaudit.py` | **一键审计流水线**: 串联上述全部工具, 对任意修改包自动出结论.md(签名路线/被改文件/桩/毒字段/官方对比) | 见内部分步依赖 |
| `panel.py` | **本地 Web 审计面板**: 浏览器提交审计任务/实时进度/报告渲染/证据浏览 (`python panel.py --port 5015`) | flask + markdown |

> apkmirror 下载的 CF 对策实测（2025-10）：headless（含 patchright）直接 1020 封禁；
> 真 Chrome 有头自动过验证；R2 文件主机拒绝一切非真浏览器 TLS（curl_cffi 伪装也没用）。
> 所以"有头 + 窗口移出屏幕 + expect_download 接管下载"是当前最优解。

## 典型工作流(复盘本次研究的打法)

```bash
# 0) 拿官方底包: apkpure 内部 API 有版本全史(微信 8.0.64 恰好缺档, apkmirror 则必须真浏览器)
python apkpure_dl.py --list com.quark.browser
python apkpure_dl.py com.quark.browser:7.14.2.872 --out ../_apkresearch/official
# (apkpure_dl 需代理时: --proxy socks5h://127.0.0.1:7891, 默认即是)

# 1) 批量摸底 —— 看签名: 原厂证书=保留原签名块(Root安装路线); testkey/个人证书=MT重签+KillerApplication(免Root)
python analyze_apk.py *.apk *.apks

# 2) 有 v1 签名的包: 直接枚举修改/删除(最有信息量的一步)
python verify_v1.py app_mod.apk
python verify_v1_full.py app_root.apks          # split 集合

# 3) v2/v3-only 的包(微信/YouTube): 靠 stub 扫描 + 时间戳指纹
python stub_scan.py app.apk other.apks
#   众数时间戳 1981-01-01 占比>95% => 重打包; 离群时间戳条目 => 被替换/注入的文件

# 4) 看 manifest 是否动过组件/进程(判定"省内存"是不是靠删子进程)
python manifest_dump.py app.apk

# 5) dex 逐级深入
python dexdiff.py   old.dex new.dex    # 字符串/字段数有没有变
python dexdeep.py   old.dex new.dex    # 新增字段(毒字段)定位
python mapdiff.py   old.dex new.dex    # 增大的字节在哪个段
python andro_diff.py old.dex new.dex --field-ref 'La3;->b1'   # 方法级语义 + 字段读写点

# 6) 跨 dex 查某字段引用(孤儿字段 => 毒字段手法)
python xref_field.py base.apk 'a3;->b1'
```

## 已知小坑

- 跑 `analyze_apk.py` / `andro_diff.py` / `xref_field.py` 时 androguard 会在当前目录留下
  `androguard.db`（它的会话缓存，无害），可随手删。
- androguard 按方法名反汇编大 dex 约需 1-2 分钟；`dexdiff.py`/`dexdeep.py`/`mapdiff.py`
  是纯标准库的秒级替代，先用它们初筛再上重炮。
- Git Bash 里给这些脚本传 `/tmp/...` 路径会在沙箱里失联，请使用真实盘符路径或工作区相对路径。
- 目录里的 `smali.jar`/`baksmali.jar`（若存在）是可选的 smali 往返工具
  （maven: org.smali/smali、org.smali/baksmali），验证 dex 可编译性时有用，不参与本工具箱流程。

## 实战结论速查

详细研究记录在 `../_apkresearch/`（按 App 分文件：01-总结 / 02-微信 / 03-夸克 / 04-YouTube / 05-支付宝 / 06-QQ / 07-高德 / 08-抖音 / 09-B站 / 10-环境与工具）。

- **掏空 .so 桩**是省内存主力: 5 字节 ELF 头替换 libUE4/libMaasSDK/liblynx/阿里保镖等重型库
- **保留官方 v1 摘要重打包** = 白送一份"修改清单", `verify_v1.py` 直接读出来
- MT管理器指纹: `bin.mt.signature.KillerApplication` + `assets/SignatureKiller/origin.apk`
  + `libSignatureKiller.so` + testkey 重签 + 全包 1981-01-01 时间戳
- 判定"毒字段": dexdeep 找到新增字段 + xref_field 确认无任何引用 = 反注入占位符
- 支付宝 10.6.50-Google-Play.apks 是官方原版(v1 摘要全匹配), 修改者留的参照底包
