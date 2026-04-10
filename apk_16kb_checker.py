#!/usr/bin/env python3
"""
APK 16KB Page Size Alignment Checker

检测 APK 中的 .so 文件是否符合 Android 16KB 页面大小对齐规范。
包含两项检查：
1. ELF 对齐检查：PT_LOAD 段的 p_align 是否 >= 16384 (2**14)
2. ZIP 对齐检查：未压缩的 .so 文件在 APK (ZIP) 中的偏移是否 16KB 对齐

对于不合规的 .so 文件，优先从项目本地 libs（fileTree 引入）与 Gradle/Maven
依赖缓存中反推来源；如未找到则通过分析 APK 内文件（嵌套归档、META-INF
版本文件、DEX 字符串池、文件路径）推测依赖来源。
"""

import argparse
import io
import os
import struct
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────── 常量 ────────────────────

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PT_GNU_RELRO = 0x6474E552
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
    relro_ok: bool = True
    relro_issue: str = ""
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
    relro_segments: list[tuple[int, int, int, int]] = []  # (offset, vaddr, filesz, memsz)
    for i in range(e_phnum):
        ph_offset = e_phoff + i * e_phentsize
        if ph_offset + e_phentsize > len(data):
            break

        p_type = struct.unpack(f"{endian}I", data[ph_offset:ph_offset + 4])[0]

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

        if p_type == PT_LOAD:
            seg = LoadSegment(
                offset=p_offset, vaddr=p_vaddr, paddr=p_paddr,
                filesz=p_filesz, memsz=p_memsz, flags=p_flags, align=p_align,
            )
            result.load_segments.append(seg)

            if min_load_align is None or p_align < min_load_align:
                min_load_align = p_align
        elif p_type == PT_GNU_RELRO:
            relro_segments.append((p_offset, p_vaddr, p_filesz, p_memsz))

    if min_load_align is None:
        result.error = "没有找到 PT_LOAD 段"
        return result

    result.min_align = min_load_align

    # RELRO 规则：若 RELRO 结束地址不是 16KB 对齐，则它必须是所在 LOAD 段的后缀。
    # 这里的“后缀”按文件区间判断（offset/filesz），以匹配 APK Analyzer 的判定。
    for relro_offset, relro_vaddr, relro_filesz, relro_memsz in relro_segments:
        relro_end = relro_vaddr + relro_memsz
        relro_end_aligned = (relro_end % ALIGN_16KB) == 0

        relro_file_end = relro_offset + relro_filesz
        relro_is_suffix = False

        for seg in result.load_segments:
            seg_file_start = seg.offset
            seg_file_end = seg.offset + seg.filesz
            if relro_offset >= seg_file_start and relro_file_end <= seg_file_end:
                relro_is_suffix = relro_file_end == seg_file_end
                if relro_is_suffix:
                    break

        if not relro_end_aligned and not relro_is_suffix:
            result.relro_ok = False
            result.relro_issue = (
                f"RELRO end=0x{relro_end:X} 非 16KB 对齐，且不是 LOAD 段后缀"
            )
            break

    result.is_aligned = (min_load_align >= ALIGN_16KB) and result.relro_ok
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


# ──────────────────── SO 来源搜索 ────────────────────


def _so_keywords(so_name: str) -> list[str]:
    """
    从 so 文件名中提取搜索关键字列表。
    例: libnative-imagetranscoder.so -> ["native-imagetranscoder", "nativeimagetranscoder",
                                          "imagetranscoder"]
    """
    base = so_name
    if base.startswith("lib"):
        base = base[3:]
    if base.endswith(".so"):
        base = base[:-3]
    base = base.lower()
    if not base:
        return []

    keywords = [base]
    # 去掉连字符的版本
    no_dash = base.replace("-", "")
    if no_dash != base:
        keywords.append(no_dash)
    # 按连字符拆分的子关键字（仅取长度 >= 7 的，避免通用词误匹配）
    if "-" in base:
        for part in base.split("-"):
            if len(part) >= 7 and part not in keywords:
                keywords.append(part)
    return keywords


def _scan_version_files(
    zf: zipfile.ZipFile,
) -> tuple[dict[str, str], dict[str, list[tuple[str, str]]]]:
    """
    读取 APK 中 META-INF/<group>_<artifact>.version 文件。

    Returns:
        versions: artifact_keyword -> group:artifact:version
        groups: group -> [(artifact, version), ...]
    """
    versions: dict[str, str] = {}
    groups: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for name in zf.namelist():
        if not (name.startswith("META-INF/") and name.endswith(".version")):
            continue
        base = name[len("META-INF/"):-len(".version")]
        if "_" not in base:
            continue
        try:
            ver = zf.read(name).decode("utf-8", errors="replace").strip()
        except OSError:
            continue
        group, artifact = base.split("_", 1)
        coord = f"{group}:{artifact}:{ver}"
        # 存储多种形式的关键字以便后续匹配
        art_lower = artifact.lower()
        versions[art_lower] = coord
        versions[art_lower.replace("-", "")] = coord
        groups[group].append((artifact, ver))
    return versions, dict(groups)


def _package_to_artifact(
    pkg: str,
    version_map: dict[str, str],
    groups: dict[str, list[tuple[str, str]]],
) -> str:
    """
    将 Java 包名转换为可能的 Maven 坐标。

    例: com.facebook.imagepipeline → com.facebook:imagepipeline (推测)
    """
    parts = pkg.split(".")
    if len(parts) < 2:
        return pkg

    artifact_candidate = parts[-1]
    art_kw = artifact_candidate.lower().replace("-", "")

    # 直接匹配 META-INF 版本文件
    if art_kw in version_map:
        return version_map[art_kw]

    # 尝试匹配已知的 group
    for i in range(len(parts) - 1, 0, -1):
        group_candidate = ".".join(parts[:i])
        if group_candidate in groups:
            for art, ver in groups[group_candidate]:
                if art.lower().replace("-", "") == art_kw:
                    return f"{group_candidate}:{art}:{ver}"
            return f"{group_candidate}:{artifact_candidate} (推测)"

    # 无匹配，使用启发式推测: 倒数第二段以上作为 group，最后一段作为 artifact
    group = ".".join(parts[:-1])
    return f"{group}:{artifact_candidate} (推测)"


def _scan_dex_for_so(zf: zipfile.ZipFile, so_names: set[str]) -> dict[str, list[str]]:
    """
    在 DEX 文件中搜索 .so 文件的引用，包括：
    1. Java 类描述符中包含的包名 (Lcom/xxx/yyy;)
    2. System.loadLibrary("xxx") 中的库名字符串

    返回 so_name -> [匹配信息] 的映射。
    """
    result: dict[str, list[str]] = defaultdict(list)
    if not so_names:
        return dict(result)

    # 构建搜索映射: keyword_bytes -> (so_name, keyword_str)
    search_map: dict[bytes, tuple[str, str]] = {}
    for so_name in so_names:
        for kw in _so_keywords(so_name):
            kw_bytes = kw.encode("utf-8")
            search_map[kw_bytes] = (so_name, kw)

    dex_entries = [n for n in zf.namelist() if n.endswith(".dex")]

    # 合法类路径字符集
    valid_class_chars = set(
        b"abcdefghijklmnopqrstuvwxyz"
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        b"0123456789/$_"
    )

    for dex_name in dex_entries:
        try:
            dex_data = zf.read(dex_name)
        except OSError:
            continue

        found_packages: dict[str, set[str]] = defaultdict(set)
        found_plain: dict[str, bool] = {}

        for kw_bytes, (so_name, kw) in search_map.items():
            if so_name in result:
                continue

            pos = 0
            while True:
                pos = dex_data.find(kw_bytes, pos)
                if pos == -1:
                    break

                # 检查是否为 Java 类描述符 (Lcom/xxx/yyy;)
                start = pos
                is_class_desc = False
                while start > 0:
                    byte = dex_data[start - 1]
                    if byte == ord("L"):
                        start -= 1
                        is_class_desc = True
                        break
                    if byte == ord("/") or byte in valid_class_chars:
                        start -= 1
                        continue
                    break

                if is_class_desc:
                    end = dex_data.find(b";", pos)
                    if end != -1 and (end - start) < 200:
                        fragment = dex_data[start:end].decode("utf-8", errors="replace")
                        # 验证: 必须以 L 开头, 包含 /, 且路径合理
                        if (fragment.startswith("L") and "/" in fragment
                                and ".." not in fragment):
                            class_path = fragment[1:]
                            parts = class_path.split("/")
                            if len(parts) >= 2:
                                pkg = ".".join(parts[:min(3, len(parts))])
                                found_packages[so_name].add(pkg)
                else:
                    # 可能是 loadLibrary 字符串引用
                    # DEX 字符串格式: ULEB128_len + MUTF-8_data + \x00
                    # 验证前后是否为字符串边界
                    if pos > 0 and dex_data[pos - 1:pos] in (
                        bytes([len(kw)]),  # 单字节长度
                        b"\x00",
                    ):
                        end = pos + len(kw_bytes)
                        if end < len(dex_data) and dex_data[end] in (0, ord(".")):
                            found_plain[so_name] = True

                pos += len(kw_bytes)

        # 整理结果
        for so_name, packages in found_packages.items():
            if so_name not in result:
                filtered = sorted(packages, key=len, reverse=True)
                for pkg in filtered[:2]:
                    result[so_name].append(pkg)

        # 对于没有找到类描述符但找到了 loadLibrary 引用的
        for so_name in found_plain:
            if so_name not in result:
                result[so_name].append("System.loadLibrary 引用")

    return dict(result)


def _scan_apk_entries(
    all_entries: list[str], so_names: set[str]
) -> dict[str, list[str]]:
    """
    在 APK 的所有文件路径中搜索与 .so 相关的条目。
    跳过 lib/ 下的 .so 文件本身。

    检查对象包括: 资源文件、.properties 文件、assets 等。
    返回 so_name -> [匹配路径] 的映射。
    """
    result: dict[str, list[str]] = defaultdict(list)

    # 构建关键字映射
    kw_map: dict[str, str] = {}  # keyword -> so_name
    for so_name in so_names:
        for kw in _so_keywords(so_name):
            if len(kw) >= 4:  # 避免过短的关键字导致误匹配
                kw_map[kw] = so_name

    for entry in all_entries:
        if entry.startswith("lib/") and entry.endswith(".so"):
            continue
        entry_lower = entry.lower()
        for kw, so_name in kw_map.items():
            if kw in entry_lower:
                result[so_name].append(entry)
                break  # 每个条目只匹配一次

    return dict(result)


def _version_sort_key(coord: str) -> tuple:
    """提取版本号用于排序比较，版本号越高 key 越大"""
    parts = coord.rsplit(":", 1)
    if len(parts) != 2:
        return (0,)
    try:
        return tuple(int(x) for x in parts[1].split("."))
    except ValueError:
        return (0,)


def _filter_gradle_versions(
    sources: list[str],
    version_map: dict[str, str],
) -> list[str]:
    """
    从多个 Gradle 缓存版本中，借助 META-INF 版本信息筛选出 APK 实际使用的版本。
    对于同一 group:artifact，优先使用 META-INF 确认的版本，否则取最新版本。
    """
    if len(sources) <= 1:
        return sources

    # 按 group:artifact 分组
    ga_coords: dict[str, list[str]] = defaultdict(list)
    other: list[str] = []
    for coord in sources:
        parts = coord.rsplit(":", 1)
        if len(parts) == 2:
            ga_coords[parts[0]].append(coord)
        else:
            other.append(coord)

    result: list[str] = []
    for ga, coords in ga_coords.items():
        artifact = ga.rsplit(":", 1)[-1]
        art_kw = artifact.lower().replace("-", "")
        if art_kw in version_map:
            result.append(version_map[art_kw])
        elif len(coords) == 1:
            result.append(coords[0])
        else:
            # META-INF 无此 artifact 信息，取最新版本
            result.append(max(coords, key=_version_sort_key))
    result.extend(other)
    return result


def trace_so_sources(
    apk_path: str,
    target_so_names: set[str],
    search_dirs: Optional[list[str]] = None,
) -> dict[str, list[str]]:
    """
    综合分析 Gradle/Maven 缓存和 APK 内所有文件，追溯 .so 文件的依赖来源。

    分析策略（按优先级）：
    0. 用户指定的外部目录中的 .aar/.jar 文件
    1. 本地 Gradle/Maven 依赖缓存（精确 Maven 坐标，通过 META-INF 交叉验证版本）
    2. APK 内嵌套的 .aar/.jar 归档
    3. META-INF 版本文件 + 关键字匹配
    4. DEX 包名搜索 + Maven 坐标推测
    5. APK 文件路径关键字匹配

    Returns:
        so_name -> [来源描述] 的映射
    """
    so_to_source: dict[str, list[str]] = defaultdict(list)
    if not target_so_names:
        return dict(so_to_source)

    # ── 策略 0: 用户指定目录（最高优先级） ──
    if search_dirs:
        print(f"  使用用户提供目录: {', '.join(search_dirs)}", file=sys.stderr)
        _scan_external_dirs(search_dirs, target_so_names, so_to_source)

    unresolved_after_user_dirs = {
        name for name in target_so_names
        if not so_to_source.get(name)
    }

    # ── 策略 1: 自动检测并扫描 Gradle/Maven 依赖缓存 ──
    auto_caches = _find_dependency_caches()
    gradle_raw: dict[str, list[str]] = defaultdict(list)
    if auto_caches and unresolved_after_user_dirs:
        print(f"  检测到本地依赖缓存: {', '.join(auto_caches)}", file=sys.stderr)
        _scan_external_dirs(auto_caches, unresolved_after_user_dirs, gradle_raw)

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            all_entries = zf.namelist()

            # 始终读取 META-INF（用于 Gradle 版本交叉验证和后续策略）
            version_map, groups = _scan_version_files(zf)

            # 交叉验证: Gradle 结果 + META-INF 筛选正确版本
            if gradle_raw:
                for so_name, coords in gradle_raw.items():
                    if not so_to_source.get(so_name):
                        filtered = _filter_gradle_versions(coords, version_map)
                        so_to_source[so_name].extend(filtered)

            # ── 以下策略仅对用户目录/Gradle 未找到的 .so 执行 ──
            apk_targets = {
                name for name in target_so_names
                if not so_to_source.get(name)
            }

            if apk_targets:
                # 策略 2: 扫描嵌套归档（.aar/.jar）
                for name in all_entries:
                    lower = name.lower()
                    if not (lower.endswith(".aar") or lower.endswith(".jar")):
                        continue
                    try:
                        archive_data = zf.read(name)
                        with zipfile.ZipFile(io.BytesIO(archive_data), "r") as inner_zf:
                            for inner_name in inner_zf.namelist():
                                if inner_name.endswith(".so"):
                                    so_name = os.path.basename(inner_name)
                                    if so_name in apk_targets:
                                        so_to_source[so_name].append(f"APK!{name}")
                    except (zipfile.BadZipFile, OSError):
                        continue

                # 策略 3: META-INF 版本文件关键字匹配
                for so_name in apk_targets:
                    for kw in _so_keywords(so_name):
                        if kw in version_map:
                            so_to_source[so_name].append(version_map[kw])
                            break

                # 策略 4: DEX 包名搜索
                unresolved = {
                    name for name in apk_targets
                    if not so_to_source.get(name)
                }
                if unresolved:
                    dex_matches = _scan_dex_for_so(zf, unresolved)
                    for so_name, packages in dex_matches.items():
                        for pkg in packages:
                            if pkg == "System.loadLibrary 引用":
                                so_to_source[so_name].append(pkg)
                            else:
                                coord = _package_to_artifact(
                                    pkg, version_map, groups
                                )
                                so_to_source[so_name].append(coord)

                # 策略 5: APK 文件路径匹配
                still_unresolved = {
                    name for name in apk_targets
                    if not so_to_source.get(name)
                }
                if still_unresolved:
                    entry_matches = _scan_apk_entries(all_entries, still_unresolved)
                    for so_name, entries in entry_matches.items():
                        if not so_to_source.get(so_name):
                            for e in entries[:3]:
                                so_to_source[so_name].append(f"APK 路径: {e}")

    except (zipfile.BadZipFile, OSError):
        # APK 无法打开时，仍使用 Gradle 原始结果（仅填充尚未命中的项）
        if gradle_raw:
            for so_name, coords in gradle_raw.items():
                if not so_to_source.get(so_name):
                    so_to_source[so_name].extend(coords)

    return dict(so_to_source)


def _scan_external_dirs(
    search_dirs: list[str],
    target_so_names: set[str],
    so_to_source: dict[str, list[str]],
) -> None:
    """在外部目录中搜索包含目标 .so 的 .aar/.jar 文件"""
    seen: set[str] = set()
    for search_dir in search_dirs:
        search_dir = os.path.expanduser(search_dir)
        if not os.path.isdir(search_dir):
            continue
        for root, _dirs, files in os.walk(search_dir):
            for f in files:
                lower = f.lower()
                if not (lower.endswith(".aar") or lower.endswith(".jar")):
                    continue
                fpath = os.path.join(root, f)
                real = os.path.realpath(fpath)
                if real in seen:
                    continue
                seen.add(real)
                try:
                    with zipfile.ZipFile(fpath, "r") as zf:
                        for entry in zf.namelist():
                            if entry.endswith(".so"):
                                so_name = os.path.basename(entry)
                                if so_name in target_so_names:
                                    so_to_source[so_name].append(
                                        _format_archive_path(fpath)
                                    )
                                    break
                except (zipfile.BadZipFile, OSError):
                    continue


def _format_archive_path(fpath: str) -> str:
    """
    尝试从归档路径中提取 Maven 坐标。
    支持 Gradle 缓存和 Maven 本地仓库两种路径格式。
    """
    parts = os.path.normpath(fpath).split(os.sep)

    # Gradle: .../files-2.1/<group>/<artifact>/<version>/<hash>/<file>
    try:
        idx = parts.index("files-2.1")
        if idx + 3 < len(parts):
            return f"{parts[idx+1]}:{parts[idx+2]}:{parts[idx+3]}"
    except ValueError:
        pass

    # Maven: .../repository/<group_path>/<artifact>/<version>/<file>
    try:
        idx = parts.index("repository")
        if idx + 3 < len(parts):
            version = parts[-2]
            artifact = parts[-3]
            group = ".".join(parts[idx+1:-3])
            return f"{group}:{artifact}:{version}"
    except ValueError:
        pass

    base = os.path.basename(fpath)
    return f"本地依赖: {base} ({fpath})"


def _find_dependency_caches() -> list[str]:
    """
    自动检测本地 Gradle 和 Maven 依赖缓存目录。

    检测位置:
    - Gradle: $GRADLE_USER_HOME/caches/modules-2/files-2.1
              或 ~/.gradle/caches/modules-2/files-2.1
    - Maven:  ~/.m2/repository
    """
    dirs: list[str] = []
    gradle_home = os.environ.get(
        "GRADLE_USER_HOME", os.path.expanduser("~/.gradle")
    )
    gradle_cache = os.path.join(
        gradle_home, "caches", "modules-2", "files-2.1"
    )
    if os.path.isdir(gradle_cache):
        dirs.append(gradle_cache)
    m2_repo = os.path.expanduser("~/.m2/repository")
    if os.path.isdir(m2_repo):
        dirs.append(m2_repo)
    return dirs


# ──────────────────── APK 检查主逻辑 ────────────────────

def check_apk(
    apk_path: str,
    check_all_abis: bool = False,
    search_dirs: Optional[list[str]] = None,
    no_source_search: bool = False,
) -> list[SoCheckResult]:
    """
    检查 APK 中所有 .so 文件的 16KB 对齐情况。

    Args:
        apk_path: APK 文件路径
        check_all_abis: 是否检查所有 ABI（默认只检查 64 位）
        search_dirs: 额外的搜索目录
        no_source_search: 是否跳过来源搜索

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
            # 遍历 APK 中所有 .so 文件（不仅是 lib/ 下的）
            so_entries = [
                name for name in zf.namelist()
                if name.endswith(".so")
            ]

            if not so_entries:
                print("该 APK 中没有找到原生库 (.so 文件)，无需检查 16KB 对齐。")
                return results

            for entry_name in sorted(so_entries):
                parts = entry_name.split("/")

                # 标准路径 lib/<abi>/<name>.so
                if entry_name.startswith("lib/") and len(parts) >= 3:
                    abi = parts[1]
                    so_name = parts[-1]
                else:
                    # 非标准位置的 .so（如 assets/ 等）
                    abi = "other"
                    so_name = parts[-1]

                # 过滤 ABI
                if not check_all_abis and abi not in TARGET_ABIS_REQUIRED:
                    if abi != "other":
                        continue
                    # other 路径下的 .so 仅在 --all-abis 时检查
                    if not check_all_abis:
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

    # 为不合规的 .so 文件查找来源
    if non_compliant_so_names and not no_source_search:
        print("正在分析 .so 来源（用户目录 + Gradle 缓存 + APK 内容）...", file=sys.stderr)

        source_index = trace_so_sources(
            apk_path, non_compliant_so_names, search_dirs
        )

        # 去重并赋值
        for result in results:
            if not result.is_compliant and result.so_name in source_index:
                seen: set[str] = set()
                deduped: list[str] = []
                for s in source_index[result.so_name]:
                    if s not in seen:
                        seen.add(s)
                        deduped.append(s)
                result.aar_sources = deduped

    return results


# ──────────────────── 输出格式化 ────────────────────

# ──────────────────── 终端颜色 ────────────────────

def _supports_color() -> bool:
    """检测当前终端是否支持 ANSI 颜色。"""
    if not sys.stdout.isatty():
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return True


_USE_COLOR = _supports_color()


def _c(text: str, code: str) -> str:
    """包装 ANSI 颜色代码，若终端不支持则原样返回。"""
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str) -> str:  return _c(t, "32")
def _red(t: str)   -> str:  return _c(t, "31")
def _yellow(t: str) -> str: return _c(t, "33")
def _bold(t: str)  -> str:  return _c(t, "1")
def _dim(t: str)   -> str:  return _c(t, "2")


import re as _re
_ANSI_ESCAPE = _re.compile(r"\033\[[0-9;]*m")


def _visible_len(s: str) -> int:
    """返回字符串去掉 ANSI 转义后的可见字符长度。"""
    return len(_ANSI_ESCAPE.sub("", s))


def _ljust(s: str, width: int) -> str:
    """感知 ANSI 颜色码的左对齐填充，等效于 s.ljust(width)。"""
    pad = width - _visible_len(s)
    return s + " " * max(pad, 0)


# ──────────────────── 工具函数 ────────────────────

def align_str(align_value: int) -> str:
    """将对齐值转换为可读字符串，如 4KB、16KB"""
    if align_value == 0:
        return "0"
    if align_value >= 1024 and align_value % 1024 == 0:
        kb = align_value // 1024
        if kb >= 1024 and kb % 1024 == 0:
            return f"{kb // 1024}MB"
        return f"{kb}KB"
    return f"{align_value}B"


def _shorten_source(source: str) -> str:
    """缩短来源显示，保留 Maven 坐标和推测标记"""
    if source.startswith("本地依赖:"):
        return source
    # 保留 "(推测)" 标记
    if source.endswith("(推测)"):
        return source
    # 去掉长路径注释 "coord (path/to/file)"
    if " (" in source and source.endswith(")"):
        return source.split(" (")[0]
    if len(source) > 50:
        return "..." + source[-47:]
    return source


def print_results(results: list[SoCheckResult], apk_path: str, verbose: bool = False):
    """打印检查结果"""
    if not results:
        return

    total = len(results)
    compliant = sum(1 for r in results if r.is_compliant)
    non_compliant = total - compliant
    apk_size = os.path.getsize(apk_path) / 1024 / 1024

    W = 128
    print()
    print(_bold("=" * W))
    print(_bold(f" APK 16KB 页面大小对齐检查报告"))
    print(f" 文件: {apk_path}")
    if non_compliant == 0:
        summary = (f" 大小: {apk_size:.2f} MB  |  共 {total} 个 .so 文件  |  "
                   + _green(f"通过: {compliant}") + f"  |  不合规: {non_compliant}")
    else:
        summary = (f" 大小: {apk_size:.2f} MB  |  共 {total} 个 .so 文件  |  通过: {compliant}  |  "
                   + _red(f"不合规: {non_compliant}"))
    print(summary)
    print(_bold("=" * W))

    if non_compliant == 0:
        print()
        print(_green(_bold(" ✅ 通过")) + _green(f"  所有 {total} 个共享库均符合 16KB 对齐规范。"))
        print()
        return

    print()
    print(_red(_bold(" ❌ 不合规")) + _red(f"  {non_compliant} 个共享库不符合 16KB 对齐规范。"))
    print()

    # ── 不合规文件汇总表 ──
    non_compliant_results = [r for r in results if not r.is_compliant]

    col_no  = 4
    col_so  = 34
    col_abi = 13
    col_elf = 16
    col_zip = 11
    col_aar = 45

    def _row(no, so, abi, elf, zip_, aar):
        return (" " + _ljust(str(no), col_no)
                + " " + _ljust(so, col_so)
                + " " + _ljust(abi, col_abi)
                + " " + _ljust(elf, col_elf)
                + " " + _ljust(zip_, col_zip)
                + " " + aar)

    sep = (" " + "-"*col_no + " " + "-"*col_so + " " + "-"*col_abi
           + " " + "-"*col_elf + " " + "-"*col_zip + " " + "-"*col_aar)

    print(_dim(_row("序号", "SO 文件", "ABI", "ELF对齐", "ZIP对齐", "来源")))
    print(_dim(sep))

    for i, r in enumerate(non_compliant_results, 1):
        elf_align = "-"
        if r.elf_result:
            elf_align = align_str(r.elf_result.min_align)
            if r.elf_result.min_align >= ALIGN_16KB and not r.elf_result.relro_ok:
                elf_align = f"{elf_align}/RELRO异常"
            if r.elf_result.min_align < ALIGN_16KB:
                elf_align = _red(elf_align)
            else:
                elf_align = _yellow(elf_align)

        if r.zip_result:
            if r.zip_result.is_compressed:
                zip_str = _dim("已压缩")
            elif r.zip_result.is_aligned:
                zip_str = _green("已对齐")
            else:
                zip_str = _red("未对齐")
        else:
            zip_str = "-"

        aar_list = [_shorten_source(a) for a in r.aar_sources] if r.aar_sources else [_dim("未找到")]

        so_name_colored = _yellow(r.so_name)
        # 第一行：序号 + 所有字段 + AAR 第一条
        print(_row(i, so_name_colored, r.abi, elf_align, zip_str, aar_list[0]))
        # AAR 额外条目另起一行
        for extra in aar_list[1:]:
            print(_row("", "", "", "", "", extra))

        # verbose: 路径 + 每个 LOAD 段详情
        if verbose:
            print(f"      {_dim('路径:')} {r.path_in_apk}")
            if r.elf_result and r.elf_result.load_segments:
                for j, seg in enumerate(r.elf_result.load_segments):
                    if seg.align >= ALIGN_16KB:
                        tag = _green("  OK")
                        align_display = _green(f"{align_str(seg.align)} (0x{seg.align:X})")
                    else:
                        tag = _red("  !!")
                        align_display = _red(f"{align_str(seg.align)} (0x{seg.align:X})")
                    print(f"      LOAD[{j}]  offset=0x{seg.offset:08X}  vaddr=0x{seg.vaddr:08X}"
                          f"  filesz=0x{seg.filesz:08X}  align={align_display}{tag}")
            if r.elf_result and not r.elf_result.relro_ok:
                print(f"      {_yellow('RELRO:')} {r.elf_result.relro_issue}  {_red('!!')}")

    print(f"\n {'─' * (W - 2)}")
    print(f" 结论: " + _red(f"{non_compliant}/{total}") + " 个共享库需要使用 16KB 对齐方式重新编译。")
    print(f" 参考: {_dim('https://developer.android.com/guide/practices/page-sizes')}")
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
                "min_align_display": align_str(r.elf_result.min_align),
                "relro_ok": r.elf_result.relro_ok,
                "relro_issue": r.elf_result.relro_issue,
                "load_segments": [
                    {
                        "offset": s.offset,
                        "align": s.align,
                        "align_display": align_str(s.align),
                    }
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
            item["sources"] = r.aar_sources
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
  %(prog)s app.apk --no-source-search
        """,
    )
    parser.add_argument("apk", nargs="?", default=None, help="APK 文件路径（不提供则交互式输入）")
    parser.add_argument(
        "--all-abis", action="store_true",
        help="检查所有 ABI（默认只检查 arm64-v8a 和 x86_64）",
    )
    parser.add_argument(
        "--search-dir", action="append", dest="search_dirs", default=[],
        help="额外的 .aar/.jar 搜索目录，用于追溯 .so 来源（可多次指定）",
    )
    parser.add_argument(
        "--no-source-search", action="store_true",
        help="跳过 .so 来源搜索",
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

    search_dirs = args.search_dirs if args.search_dirs else []
    if not args.no_source_search and not search_dirs and sys.stdin.isatty():
        raw = input(
            "可选：请输入本地 libs/.aar/.jar 目录（多个用逗号分隔，留空跳过）: "
        ).strip()
        if raw:
            for part in raw.split(","):
                p = part.strip().strip('"').strip("'")
                if p:
                    search_dirs.append(os.path.expanduser(p))

    results = check_apk(
        apk_path=apk_path,
        check_all_abis=args.all_abis,
        search_dirs=search_dirs if search_dirs else None,
        no_source_search=args.no_source_search,
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
