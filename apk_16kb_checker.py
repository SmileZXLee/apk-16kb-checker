#!/usr/bin/env python3
"""
APK 16KB Page Size Alignment Checker

检测 APK 中的 .so 文件是否符合 Android 16KB 页面大小对齐规范。
包含两项检查：
1. ELF 对齐检查：PT_LOAD 段的 p_align 是否 >= 16384 (2**14)
2. ZIP 对齐检查：未压缩的 .so 文件在 APK (ZIP) 中的偏移是否 16KB 对齐

对于不合规的 .so 文件，自动在 Gradle 缓存和指定目录中查找对应的 AAR 来源。
"""

import argparse
import glob
import os
import struct
import sys
import tempfile
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ──────────────────── 常量 ────────────────────

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
ALIGN_16KB = 16384  # 2**14
ALIGN_4KB = 4096    # 2**12

# 需要检查的 ABI（64 位架构必须合规，32 位推荐检查）
TARGET_ABIS_REQUIRED = {"arm64-v8a", "x86_64"}
TARGET_ABIS_OPTIONAL = {"armeabi-v7a", "x86"}

# ZIP 本地文件头大小
ZIP_LOCAL_HEADER_SIZE = 30


# ──────────────────── 数据类 ────────────────────

@dataclass
class LoadSegment:
    """ELF PT_LOAD 段信息"""
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    align: int


@dataclass
class ElfCheckResult:
    """单个 .so 文件的 ELF 检查结果"""
    path_in_apk: str
    abi: str
    so_name: str
    is_elf: bool = True
    is_64bit: bool = True
    load_segments: list = field(default_factory=list)
    min_align: int = 0
    is_aligned: bool = True
    error: str = ""


@dataclass
class ZipAlignResult:
    """单个 .so 文件的 ZIP 对齐检查结果"""
    path_in_apk: str
    data_offset: int
    is_compressed: bool
    is_aligned: bool  # 对于未压缩文件，数据偏移是否 16KB 对齐


@dataclass
class SoCheckResult:
    """综合检查结果"""
    path_in_apk: str
    abi: str
    so_name: str
    elf_result: Optional[ElfCheckResult] = None
    zip_result: Optional[ZipAlignResult] = None
    aar_sources: list = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        elf_ok = self.elf_result is None or self.elf_result.is_aligned
        zip_ok = self.zip_result is None or self.zip_result.is_aligned or self.zip_result.is_compressed
        return elf_ok and zip_ok


# ──────────────────── ELF 解析 ────────────────────

def parse_elf(data: bytes) -> Optional[ElfCheckResult]:
    """解析 ELF 文件，提取 PT_LOAD 段信息"""
    result = ElfCheckResult(path_in_apk="", abi="", so_name="")

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        result.is_elf = False
        result.error = "不是有效的 ELF 文件"
        return result

    # ELF class: 1=32-bit, 2=64-bit
    ei_class = data[4]
    # ELF data encoding: 1=little-endian, 2=big-endian
    ei_data = data[5]

    if ei_class == 1:
        result.is_64bit = False
    elif ei_class == 2:
        result.is_64bit = True
    else:
        result.error = f"未知的 ELF class: {ei_class}"
        return result

    endian = "<" if ei_data == 1 else ">"

    if result.is_64bit:
        # 64-bit ELF header
        if len(data) < 64:
            result.error = "ELF 文件头不完整"
            return result
        e_phoff = struct.unpack(f"{endian}Q", data[32:40])[0]
        e_phentsize = struct.unpack(f"{endian}H", data[54:56])[0]
        e_phnum = struct.unpack(f"{endian}H", data[56:58])[0]
    else:
        # 32-bit ELF header
        if len(data) < 52:
            result.error = "ELF 文件头不完整"
            return result
        e_phoff = struct.unpack(f"{endian}I", data[28:32])[0]
        e_phentsize = struct.unpack(f"{endian}H", data[42:44])[0]
        e_phnum = struct.unpack(f"{endian}H", data[44:46])[0]

    if e_phoff == 0 or e_phnum == 0:
        result.error = "没有 Program Header"
        return result

    min_load_align = None
    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        if ph_offset + e_phentsize > len(data):
            break

        p_type = struct.unpack(f"{endian}I", data[ph_offset:ph_offset + 4])[0]
        if p_type != PT_LOAD:
            continue

        if result.is_64bit:
            # 64-bit program header layout:
            # p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8)
            # p_filesz(8) p_memsz(8) p_align(8)
            p_flags = struct.unpack(f"{endian}I", data[ph_offset + 4:ph_offset + 8])[0]
            p_offset = struct.unpack(f"{endian}Q", data[ph_offset + 8:ph_offset + 16])[0]
            p_vaddr = struct.unpack(f"{endian}Q", data[ph_offset + 16:ph_offset + 24])[0]
            p_paddr = struct.unpack(f"{endian}Q", data[ph_offset + 24:ph_offset + 32])[0]
            p_filesz = struct.unpack(f"{endian}Q", data[ph_offset + 32:ph_offset + 40])[0]
            p_memsz = struct.unpack(f"{endian}Q", data[ph_offset + 40:ph_offset + 48])[0]
            p_align = struct.unpack(f"{endian}Q", data[ph_offset + 48:ph_offset + 56])[0]
        else:
            # 32-bit program header layout:
            # p_type(4) p_offset(4) p_vaddr(4) p_paddr(4)
            # p_filesz(4) p_memsz(4) p_flags(4) p_align(4)
            p_offset = struct.unpack(f"{endian}I", data[ph_offset + 4:ph_offset + 8])[0]
            p_vaddr = struct.unpack(f"{endian}I", data[ph_offset + 8:ph_offset + 12])[0]
            p_paddr = struct.unpack(f"{endian}I", data[ph_offset + 12:ph_offset + 16])[0]
            p_filesz = struct.unpack(f"{endian}I", data[ph_offset + 16:ph_offset + 20])[0]
            p_memsz = struct.unpack(f"{endian}I", data[ph_offset + 20:ph_offset + 24])[0]
            p_flags = struct.unpack(f"{endian}I", data[ph_offset + 24:ph_offset + 28])[0]
            p_align = struct.unpack(f"{endian}I", data[ph_offset + 28:ph_offset + 32])[0]

        seg = LoadSegment(
            offset=p_offset, vaddr=p_vaddr, paddr=p_paddr,
            filesz=p_filesz, memsz=p_memsz, flags=p_flags, align=p_align,
        )
        result.load_segments.append(seg)

        if min_load_align is None or p_align < min_load_align:
            min_load_align = p_align

    if min_load_align is None:
        result.error = "没有找到 PT_LOAD 段"
        return result

    result.min_align = min_load_align
    result.is_aligned = min_load_align >= ALIGN_16KB
    return result


# ──────────────────── ZIP 对齐检查 ────────────────────

def check_zip_alignment(apk_path: str, entry_name: str) -> Optional[ZipAlignResult]:
    """检查 APK 中指定条目的 ZIP 对齐情况"""
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            info = zf.getinfo(entry_name)

            # 压缩方式：0=STORED(未压缩), 8=DEFLATED(压缩)
            is_compressed = info.compress_type != zipfile.ZIP_STORED

            # 计算数据在 ZIP 中的实际偏移
            # 本地文件头(30字节) + 文件名长度 + 扩展字段长度
            # 需要读取实际的本地文件头来获取准确的 extra 字段长度
            with open(apk_path, "rb") as f:
                f.seek(info.header_offset)
                local_header = f.read(ZIP_LOCAL_HEADER_SIZE)
                if len(local_header) < ZIP_LOCAL_HEADER_SIZE:
                    return None
                fname_len = struct.unpack("<H", local_header[26:28])[0]
                extra_len = struct.unpack("<H", local_header[28:30])[0]
                data_offset = info.header_offset + ZIP_LOCAL_HEADER_SIZE + fname_len + extra_len

            is_aligned = (data_offset % ALIGN_16KB) == 0

            return ZipAlignResult(
                path_in_apk=entry_name,
                data_offset=data_offset,
                is_compressed=is_compressed,
                is_aligned=is_aligned,
            )
    except (KeyError, zipfile.BadZipFile):
        return None


# ──────────────────── AAR 搜索 ────────────────────

def build_aar_so_index(search_dirs: list[str]) -> dict[str, list[str]]:
    """
    在指定目录中搜索所有 AAR 文件，建立 so_name -> [aar_path] 的索引。
    AAR 文件中的 .so 位于 jni/<abi>/<name>.so
    """
    so_to_aar: dict[str, list[str]] = defaultdict(list)
    seen_aars = set()

    for search_dir in search_dirs:
        search_dir = os.path.expanduser(search_dir)
        if not os.path.isdir(search_dir):
            continue

        # 搜索 .aar 文件
        for root, dirs, files in os.walk(search_dir):
            for f in files:
                if not f.endswith(".aar"):
                    continue
                aar_path = os.path.join(root, f)
                real_path = os.path.realpath(aar_path)
                if real_path in seen_aars:
                    continue
                seen_aars.add(real_path)

                try:
                    with zipfile.ZipFile(aar_path, "r") as zf:
                        for entry in zf.namelist():
                            if entry.startswith("jni/") and entry.endswith(".so"):
                                so_name = os.path.basename(entry)
                                so_to_aar[so_name].append(aar_path)
                except (zipfile.BadZipFile, OSError):
                    continue

    return dict(so_to_aar)


def get_default_search_dirs() -> list[str]:
    """获取默认的 AAR 搜索目录（Gradle 缓存等）"""
    dirs = []

    # Gradle 缓存目录
    gradle_home = os.environ.get("GRADLE_USER_HOME", os.path.expanduser("~/.gradle"))
    gradle_caches = os.path.join(gradle_home, "caches")
    if os.path.isdir(gradle_caches):
        # Gradle 模块缓存中的 AAR 文件
        modules_dir = os.path.join(gradle_caches, "modules-2", "files-2.1")
        if os.path.isdir(modules_dir):
            dirs.append(modules_dir)
        # 也检查 transforms 目录
        transforms_dir = os.path.join(gradle_caches, "transforms-3")
        if os.path.isdir(transforms_dir):
            dirs.append(transforms_dir)

    # Maven 本地仓库
    m2_repo = os.path.expanduser("~/.m2/repository")
    if os.path.isdir(m2_repo):
        dirs.append(m2_repo)

    return dirs


def find_aar_for_so(
    so_name: str,
    aar_index: Optional[dict[str, list[str]]] = None,
    search_dirs: Optional[list[str]] = None,
) -> list[str]:
    """根据 .so 文件名查找可能包含它的 AAR"""
    if aar_index is not None:
        return aar_index.get(so_name, [])

    # 如果没有预建索引，实时搜索
    dirs = search_dirs or get_default_search_dirs()
    index = build_aar_so_index(dirs)
    return index.get(so_name, [])


def format_aar_path(aar_path: str) -> str:
    """尝试从 AAR 路径中提取 Maven 坐标信息"""
    parts = Path(aar_path).parts

    # 尝试匹配 Gradle 缓存路径模式:
    # ~/.gradle/caches/modules-2/files-2.1/<group>/<artifact>/<version>/<hash>/<file>.aar
    try:
        idx = parts.index("files-2.1")
        if idx + 3 < len(parts):
            group = parts[idx + 1]
            artifact = parts[idx + 2]
            version = parts[idx + 3]
            return f"{group}:{artifact}:{version} ({aar_path})"
    except (ValueError, IndexError):
        pass

    # 尝试匹配 Maven 本地仓库路径模式:
    # ~/.m2/repository/<group_path>/<artifact>/<version>/<file>.aar
    try:
        idx = parts.index("repository")
        if idx + 3 < len(parts):
            aar_file = parts[-1]
            version = parts[-2]
            artifact = parts[-3]
            group_parts = parts[idx + 1:-3]
            group = ".".join(group_parts)
            return f"{group}:{artifact}:{version} ({aar_path})"
    except (ValueError, IndexError):
        pass

    return aar_path


# ──────────────────── APK 检查主逻辑 ────────────────────

def check_apk(
    apk_path: str,
    check_all_abis: bool = False,
    search_dirs: Optional[list[str]] = None,
    no_aar_search: bool = False,
) -> list[SoCheckResult]:
    """
    检查 APK 中所有 .so 文件的 16KB 对齐情况。

    Args:
        apk_path: APK 文件路径
        check_all_abis: 是否检查所有 ABI（默认只检查 64 位）
        search_dirs: 额外的 AAR 搜索目录
        no_aar_search: 是否跳过 AAR 搜索

    Returns:
        所有 .so 文件的检查结果
    """
    if not os.path.isfile(apk_path):
        print(f"错误: 文件不存在: {apk_path}", file=sys.stderr)
        sys.exit(1)

    results: list[SoCheckResult] = []
    non_compliant_so_names: set[str] = set()

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            so_entries = [
                name for name in zf.namelist()
                if name.startswith("lib/") and name.endswith(".so")
            ]

            if not so_entries:
                print("该 APK 中没有找到原生库 (.so 文件)，无需检查 16KB 对齐。")
                return results

            for entry_name in sorted(so_entries):
                parts = entry_name.split("/")
                if len(parts) < 3:
                    continue

                abi = parts[1]
                so_name = parts[-1]

                # 过滤 ABI
                if not check_all_abis and abi not in TARGET_ABIS_REQUIRED:
                    continue

                # 读取 .so 数据并检查 ELF 对齐
                so_data = zf.read(entry_name)
                elf_result = parse_elf(so_data)
                if elf_result:
                    elf_result.path_in_apk = entry_name
                    elf_result.abi = abi
                    elf_result.so_name = so_name

                # 检查 ZIP 对齐
                zip_result = check_zip_alignment(apk_path, entry_name)

                so_result = SoCheckResult(
                    path_in_apk=entry_name,
                    abi=abi,
                    so_name=so_name,
                    elf_result=elf_result,
                    zip_result=zip_result,
                )
                results.append(so_result)

                if not so_result.is_compliant:
                    non_compliant_so_names.add(so_name)

    except zipfile.BadZipFile:
        print(f"错误: 不是有效的 ZIP/APK 文件: {apk_path}", file=sys.stderr)
        sys.exit(1)

    # 为不合规的 .so 文件查找对应的 AAR
    if non_compliant_so_names and not no_aar_search:
        all_search_dirs = get_default_search_dirs()
        if search_dirs:
            all_search_dirs.extend(search_dirs)

        if all_search_dirs:
            print("正在搜索 AAR 文件...")
            aar_index = build_aar_so_index(all_search_dirs)

            for result in results:
                if not result.is_compliant:
                    aar_paths = aar_index.get(result.so_name, [])
                    formatted = [format_aar_path(p) for p in aar_paths]
                    # 按 Maven 坐标去重（不同 hash 目录下的同一版本只保留一条）
                    seen = set()
                    deduped = []
                    for f in formatted:
                        coord = f.split(" (")[0] if " (" in f else f
                        if coord not in seen:
                            seen.add(coord)
                            deduped.append(f)
                    result.aar_sources = deduped

    return results


# ──────────────────── 输出格式化 ────────────────────

def align_str(align_value: int) -> str:
    """将对齐值转换为可读字符串"""
    if align_value == 0:
        return "0"
    import math
    power = int(math.log2(align_value)) if align_value > 0 else 0
    return f"2**{power}"


def _shorten_aar(aar_display: str) -> str:
    """缩短 AAR 显示路径，只保留 Maven 坐标部分"""
    if " (" in aar_display:
        return aar_display.split(" (")[0]
    if len(aar_display) > 50:
        return "..." + aar_display[-47:]
    return aar_display


def print_results(results: list[SoCheckResult], apk_path: str, verbose: bool = False):
    """打印检查结果"""
    if not results:
        return

    total = len(results)
    compliant = sum(1 for r in results if r.is_compliant)
    non_compliant = total - compliant
    apk_size = os.path.getsize(apk_path) / 1024 / 1024

    W = 100
    print()
    print("=" * W)
    print(f" APK 16KB 页面大小对齐检查报告")
    print(f" 文件: {apk_path}")
    print(f" 大小: {apk_size:.2f} MB  |  共 {total} 个 .so 文件  |  通过: {compliant}  |  不合规: {non_compliant}")
    print("=" * W)

    if non_compliant == 0:
        print(f"\n [通过] 所有 {total} 个共享库均符合 16KB 对齐规范。\n")
        return

    print(f"\n [不合规] {non_compliant} 个共享库不符合 16KB 对齐规范。\n")

    # ── 不合规文件汇总表 ──
    non_compliant_results = [r for r in results if not r.is_compliant]

    col_no  = 4
    col_so  = 34
    col_abi = 13
    col_elf = 11
    col_zip = 11
    col_aar = 38
    fmt = (f" {{:<{col_no}}} {{:<{col_so}}} {{:<{col_abi}}}"
           f" {{:<{col_elf}}} {{:<{col_zip}}} {{:<{col_aar}}}")
    sep = (f" {'-'*col_no} {'-'*col_so} {'-'*col_abi}"
           f" {'-'*col_elf} {'-'*col_zip} {'-'*col_aar}")

    print(fmt.format("序号", "SO 文件", "ABI", "ELF对齐", "ZIP对齐", "AAR 来源"))
    print(sep)

    for i, r in enumerate(non_compliant_results, 1):
        elf_align = align_str(r.elf_result.min_align) if r.elf_result else "-"

        if r.zip_result:
            zip_str = "已压缩" if r.zip_result.is_compressed else ("已对齐" if r.zip_result.is_aligned else "未对齐")
        else:
            zip_str = "-"

        aar_list = [_shorten_aar(a) for a in r.aar_sources] if r.aar_sources else ["未找到"]

        # 第一行：序号 + 所有字段 + AAR 第一条
        print(fmt.format(i, r.so_name, r.abi, elf_align, zip_str, aar_list[0]))
        # AAR 额外条目另起一行
        for extra in aar_list[1:]:
            print(fmt.format("", "", "", "", "", extra))

        # verbose: 每个 LOAD 段详情
        if verbose and r.elf_result and r.elf_result.load_segments:
            for j, seg in enumerate(r.elf_result.load_segments):
                tag = "  OK" if seg.align >= ALIGN_16KB else "  !!"
                print(f"      LOAD[{j}]  offset=0x{seg.offset:08X}  vaddr=0x{seg.vaddr:08X}"
                      f"  filesz=0x{seg.filesz:08X}  align={align_str(seg.align)}{tag}")

    print(f"\n {'─' * (W - 2)}")
    print(f" 结论: {non_compliant}/{total} 个共享库需要使用 16KB 对齐方式重新编译。")
    print(f" 参考: https://developer.android.com/guide/practices/page-sizes")
    print()


# ──────────────────── JSON 输出 ────────────────────

def results_to_dict(results: list[SoCheckResult], apk_path: str) -> dict:
    """将结果转换为字典，便于 JSON 输出"""
    items = []
    for r in results:
        item = {
            "path_in_apk": r.path_in_apk,
            "abi": r.abi,
            "so_name": r.so_name,
            "is_compliant": r.is_compliant,
        }
        if r.elf_result:
            item["elf"] = {
                "is_aligned": r.elf_result.is_aligned,
                "min_align": r.elf_result.min_align,
                "load_segments": [
                    {"offset": s.offset, "align": s.align}
                    for s in r.elf_result.load_segments
                ],
            }
        if r.zip_result:
            item["zip"] = {
                "is_compressed": r.zip_result.is_compressed,
                "data_offset": r.zip_result.data_offset,
                "is_aligned": r.zip_result.is_aligned,
            }
        if r.aar_sources:
            item["aar_sources"] = r.aar_sources
        items.append(item)

    total = len(results)
    compliant = sum(1 for r in results if r.is_compliant)
    return {
        "apk": apk_path,
        "total_so_files": total,
        "compliant": compliant,
        "non_compliant": total - compliant,
        "is_16kb_compliant": compliant == total,
        "details": items,
    }


# ──────────────────── CLI ────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="检测 APK 是否符合 Android 16KB 页面大小对齐规范",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s app.apk
  %(prog)s app.apk --all-abis
  %(prog)s app.apk --search-dir ./libs --search-dir /path/to/aars
  %(prog)s app.apk --json
  %(prog)s app.apk --verbose
  %(prog)s app.apk --no-aar-search
        """,
    )
    parser.add_argument("apk", nargs="?", default=None, help="APK 文件路径（不提供则交互式输入）")
    parser.add_argument(
        "--all-abis", action="store_true",
        help="检查所有 ABI（默认只检查 arm64-v8a 和 x86_64）",
    )
    parser.add_argument(
        "--search-dir", action="append", dest="search_dirs", default=[],
        help="额外的 AAR 搜索目录（可多次指定）",
    )
    parser.add_argument(
        "--no-aar-search", action="store_true",
        help="跳过 AAR 来源搜索",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="以 JSON 格式输出结果",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="显示详细信息（包括合规文件和 LOAD 段详情）",
    )

    args = parser.parse_args()

    apk_path = args.apk
    if not apk_path:
        apk_path = input("请输入 APK 文件路径: ").strip()
        if not apk_path:
            print("错误: 未提供 APK 文件路径", file=sys.stderr)
            sys.exit(1)
    # 去除可能的引号
    apk_path = apk_path.strip('"').strip("'")

    results = check_apk(
        apk_path=apk_path,
        check_all_abis=args.all_abis,
        search_dirs=args.search_dirs if args.search_dirs else None,
        no_aar_search=args.no_aar_search,
    )

    if args.json:
        import json
        data = results_to_dict(results, apk_path)
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        print_results(results, apk_path, verbose=args.verbose)

    # 退出码：0=全部合规，1=存在不合规
    has_non_compliant = any(not r.is_compliant for r in results)
    sys.exit(1 if has_non_compliant else 0)


if __name__ == "__main__":
    main()
