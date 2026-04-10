#!/usr/bin/env python3
"""
AAR 16KB Page Alignment Fixer

将 AAR 中不符合 16KB 页面对齐规范的 .so 文件修补为 16KB 对齐，
并输出新的 AAR 文件。

修补原理：
1. 修改 PT_LOAD 段的 p_align 为 16384 (16KB)
2. 若段文件偏移与虚拟地址不满足 16KB 同余条件，
   在段前插入填充字节并同步更新所有偏移字段

限制：
- RELRO 后缀对齐问题无法通过二进制修补解决，需重新链接
"""

import argparse
import os
import struct
import sys
import zipfile
from dataclasses import dataclass


# ──────────────────── 常量 ────────────────────

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PT_GNU_RELRO = 0x6474E552
ALIGN_16KB = 16384

KNOWN_ABIS = {
    "arm64-v8a", "armeabi-v7a", "x86_64", "x86",
    "armeabi", "mips", "mips64",
}


# ──────────────────── 数据类 ────────────────────

@dataclass
class ReplaceResult:
    so_path: str = ""          # 在 AAR 中的路径，如 jni/arm64-v8a/libfoo.so
    so_name: str = ""
    abi: str = ""
    replaced: bool = False
    skipped: bool = False      # AAR 中有该条目但未提供替换文件
    error: str = ""


@dataclass
class PatchResult:
    so_path: str = ""
    so_name: str = ""
    abi: str = ""
    original_align: int = 0
    was_compliant: bool = False
    patched: bool = False
    padding_added: int = 0
    relro_warning: str = ""
    error: str = ""


# ──────────────────── ELF 解析辅助 ────────────────────

def _parse_elf_header(data, endian, is_64bit):
    """解析 ELF 文件头关键字段。"""
    if is_64bit:
        return {
            "e_phoff": struct.unpack_from(f"{endian}Q", data, 32)[0],
            "e_shoff": struct.unpack_from(f"{endian}Q", data, 40)[0],
            "e_phentsize": struct.unpack_from(f"{endian}H", data, 54)[0],
            "e_phnum": struct.unpack_from(f"{endian}H", data, 56)[0],
            "e_shentsize": struct.unpack_from(f"{endian}H", data, 58)[0],
            "e_shnum": struct.unpack_from(f"{endian}H", data, 60)[0],
        }
    return {
        "e_phoff": struct.unpack_from(f"{endian}I", data, 28)[0],
        "e_shoff": struct.unpack_from(f"{endian}I", data, 32)[0],
        "e_phentsize": struct.unpack_from(f"{endian}H", data, 42)[0],
        "e_phnum": struct.unpack_from(f"{endian}H", data, 44)[0],
        "e_shentsize": struct.unpack_from(f"{endian}H", data, 46)[0],
        "e_shnum": struct.unpack_from(f"{endian}H", data, 48)[0],
    }


def _parse_phdr(data, endian, is_64bit, offset):
    """解析一个 Program Header。"""
    if is_64bit:
        return {
            "p_type": struct.unpack_from(f"{endian}I", data, offset)[0],
            "p_flags": struct.unpack_from(f"{endian}I", data, offset + 4)[0],
            "p_offset": struct.unpack_from(f"{endian}Q", data, offset + 8)[0],
            "p_vaddr": struct.unpack_from(f"{endian}Q", data, offset + 16)[0],
            "p_paddr": struct.unpack_from(f"{endian}Q", data, offset + 24)[0],
            "p_filesz": struct.unpack_from(f"{endian}Q", data, offset + 32)[0],
            "p_memsz": struct.unpack_from(f"{endian}Q", data, offset + 40)[0],
            "p_align": struct.unpack_from(f"{endian}Q", data, offset + 48)[0],
        }
    return {
        "p_type": struct.unpack_from(f"{endian}I", data, offset)[0],
        "p_offset": struct.unpack_from(f"{endian}I", data, offset + 4)[0],
        "p_vaddr": struct.unpack_from(f"{endian}I", data, offset + 8)[0],
        "p_paddr": struct.unpack_from(f"{endian}I", data, offset + 12)[0],
        "p_filesz": struct.unpack_from(f"{endian}I", data, offset + 16)[0],
        "p_memsz": struct.unpack_from(f"{endian}I", data, offset + 20)[0],
        "p_flags": struct.unpack_from(f"{endian}I", data, offset + 24)[0],
        "p_align": struct.unpack_from(f"{endian}I", data, offset + 28)[0],
    }


# ──────────────────── ELF 修补核心 ────────────────────

def patch_elf_16kb(data: bytes) -> tuple[bytes, PatchResult]:
    """
    修补 ELF .so 使其 PT_LOAD 段满足 16KB 对齐。

    策略：
    1. 若所有 PT_LOAD 段的 p_offset 与 p_vaddr 已满足 16KB 同余，
       则仅修改 p_align 字段即可。
    2. 否则在段数据前插入填充字节使同余条件成立，
       并同步更新 ELF 头、Program Header、Section Header 中的偏移字段。

    Returns:
        (修补后的字节, PatchResult)
    """
    result = PatchResult()

    if len(data) < 64 or data[:4] != ELF_MAGIC:
        result.error = "不是有效的 ELF 文件"
        return data, result

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        result.error = f"未知 ELF class: {ei_class}"
        return data, result

    is_64bit = ei_class == 2
    endian = "<" if ei_data == 1 else ">"

    hdr = _parse_elf_header(data, endian, is_64bit)
    e_phoff = hdr["e_phoff"]
    e_shoff = hdr["e_shoff"]
    e_phentsize = hdr["e_phentsize"]
    e_phnum = hdr["e_phnum"]
    e_shentsize = hdr["e_shentsize"]
    e_shnum = hdr["e_shnum"]

    if e_phoff == 0 or e_phnum == 0:
        result.error = "没有 Program Header"
        return data, result

    # ── 解析所有 Program Header ──
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            break
        phdrs.append(_parse_phdr(data, endian, is_64bit, off))

    load_segs = [(i, ph) for i, ph in enumerate(phdrs) if ph["p_type"] == PT_LOAD]
    if not load_segs:
        result.error = "没有 PT_LOAD 段"
        return data, result

    min_align = min(ph["p_align"] for _, ph in load_segs)
    result.original_align = min_align

    # ── 检查 RELRO（与 apk_16kb_checker 规则完全一致）──
    # 规则：若 RELRO 结束地址不是 16KB 对齐，则它必须是所属 LOAD 段的文件区间后缀；
    # 否则判为不合规。使用文件区间（offset/filesz）判断，匹配 Android Studio APK Analyzer。
    for relro_ph in phdrs:
        if relro_ph["p_type"] != PT_GNU_RELRO:
            continue
        relro_end = relro_ph["p_vaddr"] + relro_ph["p_memsz"]
        relro_end_aligned = (relro_end % ALIGN_16KB) == 0

        relro_file_end = relro_ph["p_offset"] + relro_ph["p_filesz"]
        relro_is_suffix = False

        for _, seg in load_segs:
            seg_file_start = seg["p_offset"]
            seg_file_end = seg["p_offset"] + seg["p_filesz"]
            if relro_ph["p_offset"] >= seg_file_start and relro_file_end <= seg_file_end:
                relro_is_suffix = relro_file_end == seg_file_end
                if relro_is_suffix:
                    break

        if not relro_end_aligned and not relro_is_suffix:
            result.relro_warning = (
                f"RELRO end=0x{relro_end:X} 非 16KB 对齐且非后缀，"
                "需重新链接修复"
            )
            break

    # ── 是否已合规 ──
    already_aligned = min_align >= ALIGN_16KB
    if already_aligned and not result.relro_warning:
        result.was_compliant = True
        return data, result
    if already_aligned:
        # p_align 够了但 RELRO 有问题，无法二进制修补
        result.error = "p_align 已 16KB，但 RELRO 问题需重新链接"
        return data, result

    # ── 按文件偏移排序 LOAD 段 ──
    load_segs.sort(key=lambda x: x[1]["p_offset"])

    # ── 计算每个 LOAD 段需要的前置填充 ──
    insertions: list[tuple[int, int]] = []  # (原始插入位置, 填充大小)
    acc_shift = 0

    for _, seg in load_segs:
        new_off = seg["p_offset"] + acc_shift
        if new_off == 0:
            # 首段（包含 ELF 头），无法在其前方插入填充
            if seg["p_vaddr"] % ALIGN_16KB != 0:
                result.error = (
                    f"首 LOAD 段 vaddr=0x{seg['p_vaddr']:X} 非 16KB 对齐，"
                    "无法修补"
                )
                return data, result
            continue

        cur_mod = new_off % ALIGN_16KB
        tgt_mod = seg["p_vaddr"] % ALIGN_16KB
        delta = (tgt_mod - cur_mod) % ALIGN_16KB if cur_mod != tgt_mod else 0
        if delta > 0:
            insertions.append((seg["p_offset"], delta))
            acc_shift += delta

    total_shift = acc_shift

    # ── 情况 A：无需填充，仅修改 p_align ──
    if total_shift == 0:
        buf = bytearray(data)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if phdrs[i]["p_type"] == PT_LOAD:
                if is_64bit:
                    struct.pack_into(f"{endian}Q", buf, off + 48, ALIGN_16KB)
                else:
                    struct.pack_into(f"{endian}I", buf, off + 28, ALIGN_16KB)
        result.patched = True
        result.padding_added = 0
        return bytes(buf), result

    # ── 情况 B：需要插入填充 ──
    insertions.sort()

    def _new_offset(orig: int) -> int:
        """原始文件偏移 → 新文件偏移"""
        shift = 0
        for pos, d in insertions:
            if orig >= pos:
                shift += d
        return orig + shift

    # 拼接新文件（在各插入点加入零填充）
    chunks: list[bytes] = []
    src = 0
    for pos, delta in insertions:
        chunks.append(data[src:pos])
        chunks.append(b"\x00" * delta)
        src = pos
    chunks.append(data[src:])

    new_data = bytearray(b"".join(chunks))
    assert len(new_data) == len(data) + total_shift

    # 更新 ELF 文件头中的偏移
    new_phoff = _new_offset(e_phoff)
    new_shoff = _new_offset(e_shoff) if e_shoff else 0

    if is_64bit:
        struct.pack_into(f"{endian}Q", new_data, 32, new_phoff)
        if e_shoff:
            struct.pack_into(f"{endian}Q", new_data, 40, new_shoff)
    else:
        struct.pack_into(f"{endian}I", new_data, 28, new_phoff)
        if e_shoff:
            struct.pack_into(f"{endian}I", new_data, 32, new_shoff)

    # 更新所有 Program Header 的 p_offset（及 PT_LOAD 的 p_align）
    for i in range(e_phnum):
        ph_off = new_phoff + i * e_phentsize
        if ph_off + e_phentsize > len(new_data):
            break
        ph = _parse_phdr(new_data, endian, is_64bit, ph_off)
        updated_poff = _new_offset(ph["p_offset"])

        if is_64bit:
            struct.pack_into(f"{endian}Q", new_data, ph_off + 8, updated_poff)
            if ph["p_type"] == PT_LOAD:
                struct.pack_into(f"{endian}Q", new_data, ph_off + 48, ALIGN_16KB)
        else:
            struct.pack_into(f"{endian}I", new_data, ph_off + 4, updated_poff)
            if ph["p_type"] == PT_LOAD:
                struct.pack_into(f"{endian}I", new_data, ph_off + 28, ALIGN_16KB)

    # 更新所有 Section Header 的 sh_offset
    if new_shoff and e_shnum:
        for i in range(e_shnum):
            sh_off = new_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(new_data):
                break
            if is_64bit:
                orig_soff = struct.unpack_from(
                    f"{endian}Q", new_data, sh_off + 24
                )[0]
                struct.pack_into(
                    f"{endian}Q", new_data, sh_off + 24, _new_offset(orig_soff)
                )
            else:
                orig_soff = struct.unpack_from(
                    f"{endian}I", new_data, sh_off + 16
                )[0]
                struct.pack_into(
                    f"{endian}I", new_data, sh_off + 16, _new_offset(orig_soff)
                )

    # ── 验证修补结果 ──
    patched_bytes = bytes(new_data)
    if not _verify_patched_elf(patched_bytes, endian, is_64bit):
        result.error = "修补后验证失败，放弃修改"
        return data, result

    result.patched = True
    result.padding_added = total_shift
    return patched_bytes, result


def _verify_patched_elf(data: bytes, endian: str, is_64bit: bool) -> bool:
    """验证修补后的 ELF 是否满足 16KB 对齐要求。"""
    hdr = _parse_elf_header(data, endian, is_64bit)
    for i in range(hdr["e_phnum"]):
        off = hdr["e_phoff"] + i * hdr["e_phentsize"]
        if off + hdr["e_phentsize"] > len(data):
            return False
        ph = _parse_phdr(data, endian, is_64bit, off)
        if ph["p_type"] == PT_LOAD:
            if ph["p_align"] < ALIGN_16KB:
                return False
            if ph["p_offset"] % ALIGN_16KB != ph["p_vaddr"] % ALIGN_16KB:
                return False
    return True


# ──────────────────── AAR 处理 ────────────────────

def _detect_abi(entry_path: str) -> str:
    """从 ZIP 条目路径推断 ABI。"""
    parts = entry_path.replace("\\", "/").split("/")
    for p in parts:
        if p in KNOWN_ABIS:
            return p
    return "unknown"


def fix_aar(
    aar_path: str,
    output_path: str,
    dry_run: bool = False,
) -> list[PatchResult]:
    """
    处理 AAR 文件：修补其中所有不合规的 .so 文件。

    Args:
        aar_path: 输入 AAR 路径
        output_path: 输出 AAR 路径
        dry_run: 仅检查，不实际修补

    Returns:
        每个 .so 的修补结果列表
    """
    results: list[PatchResult] = []

    with zipfile.ZipFile(aar_path, "r") as zin:
        so_entries = [n for n in zin.namelist() if n.endswith(".so")]

        if not so_entries:
            print("AAR 中没有找到 .so 文件")
            return results

        patched_data: dict[str, bytes] = {}

        for entry in so_entries:
            data = zin.read(entry)
            new_data, pr = patch_elf_16kb(data)
            pr.so_path = entry
            pr.so_name = entry.rsplit("/", 1)[-1]
            pr.abi = _detect_abi(entry)
            results.append(pr)

            if not dry_run and pr.patched:
                patched_data[entry] = new_data

        if dry_run or not patched_data:
            return results

        # 生成新的 AAR（保留所有原始条目属性）
        with zipfile.ZipFile(output_path, "w") as zout:
            for item in zin.infolist():
                if item.filename in patched_data:
                    # 修补过的 .so 以 STORED 方式写入
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, patched_data[item.filename])
                else:
                    zout.writestr(item, zin.read(item.filename))

    return results


# ──────────────────── SO 替换（重新链接后的版本） ────────────────────

def _build_replace_map(replace_dir: str) -> dict[str, bytes]:
    """
    扫描替换目录，返回 {匹配键: 文件内容}。

    支持两种目录结构：
    1. ABI 子目录：replace_dir/arm64-v8a/libfoo.so
       匹配键为 "arm64-v8a/libfoo.so"（与 AAR 中 jni/ 后的相对路径比较）
    2. 平铺：replace_dir/libfoo.so
       匹配键为 "libfoo.so"（按文件名匹配所有 ABI）
    """
    replace_map: dict[str, bytes] = {}
    replace_dir = os.path.expanduser(replace_dir)

    for entry in os.scandir(replace_dir):
        if entry.is_dir() and entry.name in KNOWN_ABIS:
            # ABI 子目录模式
            for so_entry in os.scandir(entry.path):
                if so_entry.is_file() and so_entry.name.endswith(".so"):
                    key = f"{entry.name}/{so_entry.name}"
                    with open(so_entry.path, "rb") as f:
                        replace_map[key] = f.read()
        elif entry.is_file() and entry.name.endswith(".so"):
            # 平铺模式
            with open(entry.path, "rb") as f:
                replace_map[entry.name] = f.read()

    return replace_map


def replace_sos_in_aar(
    aar_path: str,
    output_path: str,
    replace_dir: str,
) -> list[ReplaceResult]:
    """
    将 AAR 中的 .so 文件替换为指定目录中的版本（重新编译后的文件）。

    目录结构示例：
      replace_dir/
        arm64-v8a/libfoo.so   <- 仅替换对应 ABI
        armeabi-v7a/libfoo.so
      或
      replace_dir/
        libfoo.so             <- 替换所有 ABI
    """
    results: list[ReplaceResult] = []
    replace_map = _build_replace_map(replace_dir)

    if not replace_map:
        print(f"错误: 替换目录中没有找到 .so 文件: {replace_dir}", file=sys.stderr)
        return results

    with zipfile.ZipFile(aar_path, "r") as zin:
        so_entries = [n for n in zin.namelist() if n.endswith(".so")]
        if not so_entries:
            print("AAR 中没有找到 .so 文件")
            return results

        replaced_data: dict[str, bytes] = {}

        for entry in so_entries:
            rr = ReplaceResult(
                so_path=entry,
                so_name=entry.rsplit("/", 1)[-1],
                abi=_detect_abi(entry),
            )
            results.append(rr)

            # 尝试精确匹配（ABI/名称）
            parts = entry.replace("\\", "/").split("/")
            # AAR 条目格式通常为 jni/<abi>/<name>.so
            abi_name_key = None
            so_name_key = rr.so_name
            for i, p in enumerate(parts):
                if p in KNOWN_ABIS and i + 1 < len(parts):
                    abi_name_key = f"{p}/{parts[i + 1]}"
                    break

            new_data = None
            if abi_name_key and abi_name_key in replace_map:
                new_data = replace_map[abi_name_key]
            elif so_name_key in replace_map:
                new_data = replace_map[so_name_key]

            if new_data is not None:
                replaced_data[entry] = new_data
                rr.replaced = True
            else:
                rr.skipped = True

        if not replaced_data:
            print("没有找到可替换的 .so 文件（文件名不匹配）")
            return results

        with zipfile.ZipFile(output_path, "w") as zout:
            for item in zin.infolist():
                if item.filename in replaced_data:
                    item.compress_type = zipfile.ZIP_STORED
                    zout.writestr(item, replaced_data[item.filename])
                else:
                    zout.writestr(item, zin.read(item.filename))

    return results


def print_replace_results(results: list[ReplaceResult]) -> None:
    if not results:
        return

    abis: dict[str, list[ReplaceResult]] = {}
    for r in results:
        abis.setdefault(r.abi, []).append(r)

    for abi, items in sorted(abis.items()):
        print(f"\n{'─' * 64}")
        print(f"  ABI: {abi}")
        print(f"{'─' * 64}")
        for r in items:
            if r.replaced:
                status = "✓ 已替换"
            elif r.skipped:
                status = "- 未提供替换文件，保留原版"
            else:
                status = f"✗ {r.error}"
            print(f"  {r.so_name:<40} {status}")

    replaced = sum(1 for r in results if r.replaced)
    skipped = sum(1 for r in results if r.skipped)
    print(f"\n{'═' * 64}")
    print(f"  共 {len(results)} 个 SO: {replaced} 已替换, {skipped} 保留原版")
    print(f"{'═' * 64}")


# ──────────────────── 输出格式化 ────────────────────

def _align_str(val: int) -> str:
    if val == 0:
        return "0"
    kb = val // 1024
    if kb > 0 and kb * 1024 == val:
        return f"{kb}KB"
    return str(val)


def print_results(results: list[PatchResult], dry_run: bool = False) -> None:
    if not results:
        return

    # 按 ABI 分组
    abis: dict[str, list[PatchResult]] = {}
    for r in results:
        abis.setdefault(r.abi, []).append(r)

    for abi, items in sorted(abis.items()):
        print(f"\n{'─' * 64}")
        print(f"  ABI: {abi}")
        print(f"{'─' * 64}")
        print(f"  {'SO 文件':<38} {'原对齐':>6}  状态")
        print(f"  {'─' * 38} {'─' * 6}  {'─' * 16}")

        for r in items:
            align = _align_str(r.original_align)

            if r.was_compliant:
                status = "✓ 已合规"
            elif r.error:
                status = f"✗ {r.error}"
            elif r.patched:
                if dry_run:
                    if r.padding_added > 0:
                        status = f"→ 需填充 +{r.padding_added} 字节"
                    else:
                        status = "→ 仅需改 p_align"
                else:
                    if r.padding_added > 0:
                        status = f"✓ 已修补 (+{r.padding_added} 字节填充)"
                    else:
                        status = "✓ 已修补 (仅改 p_align)"
            else:
                status = "? 未处理"

            print(f"  {r.so_name:<38} {align:>6}  {status}")

            if r.relro_warning:
                print(f"    ⚠ {r.relro_warning}")

    # 汇总
    total = len(results)
    compliant = sum(1 for r in results if r.was_compliant)
    patched = sum(1 for r in results if r.patched)
    failed = sum(1 for r in results if r.error and not r.was_compliant)
    relro = sum(1 for r in results if r.relro_warning)

    print(f"\n{'═' * 64}")
    action = "检查" if dry_run else "修补"
    print(f"  共 {total} 个 SO: {compliant} 已合规, ", end="")
    if dry_run:
        need_fix = sum(1 for r in results if r.patched or (r.error and not r.was_compliant))
        print(f"{need_fix} 需修补, {failed} 无法修补")
    else:
        print(f"{patched} 已修补, {failed} 失败")
    if relro:
        print(f"  ⚠ {relro} 个 SO 存在 RELRO 问题，需重新链接修复")
    print(f"{'═' * 64}")


# ──────────────────── CLI ────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="将 AAR 中不符合 16KB 页面对齐的 .so 文件修补为 16KB 对齐",
    )
    parser.add_argument("aar_path", help="输入 AAR 文件路径")
    parser.add_argument(
        "-o", "--output",
        help="输出 AAR 路径（默认: 原文件名_16kb.aar）",
    )
    parser.add_argument(
        "-n", "--dry-run",
        action="store_true",
        help="仅检查，不实际修补",
    )
    parser.add_argument(
        "-r", "--replace-dir",
        metavar="DIR",
        help=(
            "用指定目录中重新编译的 .so 替换 AAR 内对应文件。"
            "目录结构：DIR/<abi>/libfoo.so（精确匹配 ABI）"
            "或 DIR/libfoo.so（替换全部 ABI）"
        ),
    )
    args = parser.parse_args()

    aar_path = os.path.expanduser(args.aar_path)
    if not os.path.isfile(aar_path):
        print(f"错误: 文件不存在: {aar_path}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        output_path = os.path.expanduser(args.output)
    else:
        base, ext = os.path.splitext(aar_path)
        output_path = f"{base}_16kb{ext}"

    print(f"输入: {aar_path}")

    if args.replace_dir:
        replace_dir = os.path.expanduser(args.replace_dir)
        if not os.path.isdir(replace_dir):
            print(f"错误: 替换目录不存在: {replace_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"替换目录: {replace_dir}")
        print(f"输出: {output_path}")
        results = replace_sos_in_aar(aar_path, output_path, replace_dir)
        print_replace_results(results)
        replaced = sum(1 for r in results if r.replaced)
        if replaced > 0:
            print(f"\n  输出文件: {output_path}")
    else:
        if not args.dry_run:
            print(f"输出: {output_path}")
        results = fix_aar(aar_path, output_path, dry_run=args.dry_run)
        print_results(results, dry_run=args.dry_run)
        if not args.dry_run:
            patched = sum(1 for r in results if r.patched)
            if patched > 0:
                print(f"\n  输出文件: {output_path}")


if __name__ == "__main__":
    main()
