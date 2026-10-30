#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA Android 逆向分析一站式自动化工具 (rea_tool.py)
用于解决 .apks 分包解压、REA (Reverse Engineer Anything) 环境依赖配置 (JADX/JDK)、
以及调用 REA 进行安卓应用静态解构、类搜索与引用追踪的完整流水线。
"""

import os
import sys
import json

# 确保在 Windows 终端环境下输出 utf-8 字符不崩溃
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import shutil
import zipfile
import hashlib
import logging
import argparse
import subprocess
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

# 配置规范化日志，输出带时间戳与级别的中文日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("rea_tool")

# 官方指定的 JADX Headless MCP 0.7.1 版本信息与校验哈希
PINNED_JADX_URL = "https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar"
PINNED_JADX_SHA256 = "6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"

# 本地常见 JDK 优先候选路径（解决 Windows 环境变量未全局声明的问题）
CANDIDATE_JDK_PATHS = [
    Path(r"D:\PortableTools\jdk-21.0.8"),
    Path(os.environ.get("JAVA_HOME", "")) if os.environ.get("JAVA_HOME") else None,
]


def calculate_sha256(file_path: Path) -> str:
    """计算文件的 SHA-256 哈希值用于安全性校验"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


def ensure_java_home() -> str:
    """探测并配置 JDK 21+ 路径，优先采用便携版高质量 JDK"""
    for candidate in CANDIDATE_JDK_PATHS:
        if candidate and candidate.exists():
            java_bin = candidate / "bin" / ("java.exe" if os.name == "nt" else "java")
            if java_bin.exists():
                logger.info(f"成功定位到可用 JDK: {candidate}")
                os.environ["JAVA_HOME"] = str(candidate)
                # 注入 PATH 前列，避免被低版本 java 干扰
                bin_dir = str(candidate / "bin")
                if bin_dir not in os.environ["PATH"]:
                    os.environ["PATH"] = bin_dir + os.pathsep + os.environ["PATH"]
                return str(candidate)

    # 若未找到候选，检查 PATH 中的 java
    java_in_path = shutil.which("java")
    if java_in_path:
        logger.info(f"使用 PATH 中的默认 Java: {java_in_path}")
        return str(Path(java_in_path).parent.parent)

    raise RuntimeError("未检测到 JDK 17+ 运行环境，请检查 D:\\PortableTools\\jdk-21.0.8 或配置 JAVA_HOME。")


def ensure_jadx_jar(target_lib_dir: Path) -> Path:
    """
    确保 jadx-headless-mcp-0.7.1-all.jar 在本地存在且校验哈希通过。
    本地检索顺序：项目 apktools/lib -> 用户目录 ~/.local/share/rea/android -> 触发静默下载
    """
    target_lib_dir.mkdir(parents=True, exist_ok=True)
    local_jar = target_lib_dir / "jadx-headless-mcp-0.7.1-all.jar"
    user_jar = Path.home() / ".local" / "share" / "rea" / "android" / "jadx-headless-mcp-0.7.1-all.jar"

    for candidate in [local_jar, user_jar]:
        if candidate.exists():
            try:
                digest = calculate_sha256(candidate)
                if digest == PINNED_JADX_SHA256:
                    logger.info(f"已就绪 JADX MCP 驱动 Jar 包: {candidate}")
                    return candidate
                else:
                    logger.warning(f"Jar 包哈希不符 ({candidate})，预期: {PINNED_JADX_SHA256}，实际: {digest}")
            except Exception as e:
                logger.error(f"校验 Jar 包异常: {e}")

    # 若均不存在或损坏，则自动下载到 local_jar
    logger.info(f"正在从官方源下载 JADX Headless MCP 依赖 (约 40MB): {PINNED_JADX_URL}")
    temp_target = local_jar.with_suffix(".tmp")
    try:
        req = urllib.request.Request(PINNED_JADX_URL, headers={"User-Agent": "Mozilla/5.0 rea_tool"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(temp_target, "wb") as out_file:
            shutil.copyfileobj(resp, out_file)

        digest = calculate_sha256(temp_target)
        if digest != PINNED_JADX_SHA256:
            if temp_target.exists():
                temp_target.unlink()
            raise ValueError(f"下载文件 SHA-256 校验失败: 预期 {PINNED_JADX_SHA256}, 实际 {digest}")

        temp_target.rename(local_jar)
        logger.info(f"依赖下载与哈希校验完成: {local_jar}")
        return local_jar
    except Exception as e:
        if temp_target.exists():
            temp_target.unlink()
        raise RuntimeError(f"下载 JADX MCP 依赖失败，请检查网络连接或手动放入: {e}")


def unpack_apks_if_needed(target_path: Path, output_dir: Optional[Path] = None) -> Tuple[Path, List[Path]]:
    """
    识别目标包格式：
    如果是 .apks 分包压缩文件，自动解压出 base.apk 以及所有 split_config.*.apk。
    如果是普通的 .apk 文件，则直接返回该文件。
    返回: (主 apk 路径, 所有拆分包列表)
    """
    if not target_path.exists():
        raise FileNotFoundError(f"目标文件不存在: {target_path}")

    if target_path.suffix.lower() == ".apk":
        logger.info(f"输入为单个独立 APK: {target_path.name}")
        return target_path, [target_path]

    if target_path.suffix.lower() == ".apks":
        logger.info(f"检测到 APKS 分包文件: {target_path.name}，正在执行自动解包...")
        if output_dir is None:
            # 默认解压到同级目录下的 _unpacked 文件夹
            output_dir = target_path.parent / f"{target_path.stem}_unpacked"

        output_dir.mkdir(parents=True, exist_ok=True)
        split_apks = []
        base_apk: Optional[Path] = None

        with zipfile.ZipFile(target_path, "r") as zf:
            for item in zf.infolist():
                if item.filename.endswith(".apk"):
                    extracted_path = output_dir / Path(item.filename).name
                    with zf.open(item) as src, open(extracted_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    split_apks.append(extracted_path)
                    logger.info(f"  已解包子包: {extracted_path.name} ({extracted_path.stat().st_size // 1024} KB)")
                    if extracted_path.name == "base.apk":
                        base_apk = extracted_path

        if not base_apk:
            # 如果没有命名为 base.apk，默认选取体积最大的 apk 作为主包
            split_apks.sort(key=lambda p: p.stat().st_size, reverse=True)
            base_apk = split_apks[0]
            logger.warning(f"未明确命名 base.apk，自动选定最大体积子包为主应用包: {base_apk.name}")

        logger.info(f"APKS 解包完成，主入口包: {base_apk}")
        return base_apk, split_apks

    raise ValueError(f"不支持的文件扩展名: {target_path.suffix}，仅支持 .apk 或 .apks")


def run_rea_command(subcommand: str, args: List[str], env: Dict[str, str], full_output: bool = False) -> str:
    """
    通过 pnpm dlx 统一调用 REA CLI 工具链，捕获并处理标准输出
    """
    # Windows 下优先调用 pnpm.cmd / pnpm.ps1
    pnpm_cmd = "pnpm.cmd" if os.name == "nt" else "pnpm"
    cmd = [pnpm_cmd, "dlx", "rea-agents@latest", subcommand] + args
    if full_output:
        cmd.append("--full-output")

    logger.info(f"执行 REA 核心命令: {subcommand} {' '.join(args[:2])} ...")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env
        )
        if proc.returncode != 0:
            logger.error(f"REA 命令执行失败 (退出码 {proc.returncode}):\n{proc.stderr}")
            return proc.stderr or proc.stdout
        return proc.stdout
    except Exception as e:
        logger.error(f"调度 REA 失败: {e}")
        raise


def main():
    parser = argparse.ArgumentParser(
        description="REA Android APK/APKS 自动化逆向与解包分析工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例用法:
  python rea_tool.py inspect "d:\\path\\to\\app.apks"
  python rea_tool.py search "d:\\path\\to\\app.apk" --query MainActivity
  python rea_tool.py method "d:\\path\\to\\app.apk" --class-name com.example.MainActivity --method-name onCreate
  python rea_tool.py trace "d:\\path\\to\\app.apk" --class-name com.example.MainActivity
"""
    )
    parser.add_argument("action", choices=["inspect", "search", "class", "method", "trace", "unpack"], help="逆向分析动作")
    parser.add_argument("target", help="待分析的 .apk 或 .apks 文件路径")
    parser.add_argument("--query", "-q", default="", help="类名或特征搜索关键字")
    parser.add_argument("--class-name", "-c", default="", help="指定反编译或追踪的目标类全限定名")
    parser.add_argument("--method-name", "-m", default="", help="指定反编译的目标方法名")
    parser.add_argument("--out-dir", "-o", default=None, help="APKS 解包输出目标目录")
    parser.add_argument("--format", default="text", choices=["text", "json"], help="输出结果呈现格式")

    args = parser.parse_args()

    # 1. 确保环境与依赖
    script_dir = Path(__file__).resolve().parent
    lib_dir = script_dir / "lib"

    target_path = Path(args.target).resolve()
    out_dir = Path(args.out_dir).resolve() if args.out_dir else None

    # 解包 APK / APKS
    main_apk, all_splits = unpack_apks_if_needed(target_path, out_dir)

    if args.action == "unpack":
        print(f"\n[OK] APKS 解包完成！")
        print(f"主 APK: {main_apk}")
        print("所有拆分包:")
        for s in all_splits:
            print(f" - {s.name} ({s.stat().st_size // 1024} KB)")
        return

    # 准备 REA 运行环境
    java_home = ensure_java_home()
    jadx_jar = ensure_jadx_jar(lib_dir)

    run_env = os.environ.copy()
    run_env["JAVA_HOME"] = java_home
    run_env["REA_JADX_MCP_JAR"] = str(jadx_jar)

    # 2. 调度对应 REA 命令
    result = ""
    if args.action == "inspect":
        cmd_args = [str(main_apk)]
        if args.format == "json":
            cmd_args.extend(["--format", "json"])
        result = run_rea_command("inspect-android-package", cmd_args, run_env)

    elif args.action == "search":
        cmd_args = [str(main_apk)]
        if args.query:
            cmd_args.append(args.query)
        if args.format == "json":
            cmd_args.extend(["--format", "json"])
        result = run_rea_command("search-android-classes", cmd_args, run_env)

    elif args.action == "class":
        if not args.class_name:
            logger.error("类审查必须提供 --class-name 参数")
            sys.exit(1)
        cmd_args = [str(main_apk), args.class_name]
        if args.format == "json":
            cmd_args.extend(["--format", "json"])
        result = run_rea_command("inspect-android-class", cmd_args, run_env)

    elif args.action == "method":
        if not args.class_name or not args.method_name:
            logger.error("反编译方法必须提供 --class-name 和 --method-name 参数")
            sys.exit(1)
        cmd_args = [str(main_apk), args.class_name, args.method_name]
        result = run_rea_command("inspect-android-method", cmd_args, run_env)

    elif args.action == "trace":
        if not args.class_name:
            logger.error("调用追踪必须提供 --class-name 参数")
            sys.exit(1)
        cmd_args = [str(main_apk), args.class_name]
        if args.method_name:
            cmd_args.extend(["--method-name", args.method_name])
        result = run_rea_command("trace-android-references", cmd_args, run_env)

    print("\n" + "=" * 60)
    print(f" REA 逆向分析报告 [{args.action.upper()}] - {target_path.name}")
    print("=" * 60)
    print(result)


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        logger.error(f"处理失败: {ex}", exc_info=True)
        sys.exit(1)
