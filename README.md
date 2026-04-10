# apk-16kb-checker

检测 APK 是否符合 Android 16KB 页面大小对齐规范。

从 Android 15 开始，设备开始支持 16KB 页面大小。自 2025 年 11 月 1 日起，Google Play 要求所有以 Android 15+ 为目标的应用必须支持 16KB 页面大小。此工具帮助你快速检测 APK 中的 .so 文件是否合规，并自动追溯依赖来源。

## 功能

- **ELF 对齐检查**: 解析 .so 文件的 ELF PT_LOAD 段，检查 `p_align` 是否 >= 16384 (16KB)，并额外检查 RELRO 结束位置是否满足 16KB 规则
- **ZIP 对齐检查**: 检查未压缩的 .so 文件在 APK (ZIP) 中的数据偏移是否 16KB 对齐
- **来源追溯**: 优先从你手动提供的本地目录（`--search-dir` 或交互输入）与本地 Gradle/Maven 依赖缓存中反推精确来源；如未找到则通过分析 APK 内文件（嵌套归档、META-INF 版本文件、DEX 字符串池、文件路径）推测依赖来源
- **多种输出格式**: 支持终端表格输出、详细模式（`--verbose`）和 JSON 格式输出（`--json`）
- **纯 Python 实现**: 无需安装 Android SDK 或 NDK，无第三方依赖

## 安装

无需安装，直接使用 Python 3.10+ 运行：

```bash
git clone https://github.com/SmileZXLee/apk-16kb-checker.git
cd apk-16kb-checker
```

## 使用方法

```bash
# 基本检查（可交互式输入路径，也可直接传参）
python3 apk_16kb_checker.py
python3 apk_16kb_checker.py app.apk

# 检查所有 ABI（默认只检查 arm64-v8a 和 x86_64）
python3 apk_16kb_checker.py app.apk --all-abis

# 详细模式：显示每个 ELF LOAD 段的对齐信息
python3 apk_16kb_checker.py app.apk --verbose

# JSON 格式输出（适合脚本集成）
python3 apk_16kb_checker.py app.apk --json

# 指定额外的搜索目录（用于追溯 .so 来源）
python3 apk_16kb_checker.py app.apk --search-dir ./libs --search-dir /path/to/aars

# 未指定 --search-dir 时，程序会交互询问一次本地目录（回车可跳过）
python3 apk_16kb_checker.py app.apk

# 跳过来源搜索
python3 apk_16kb_checker.py app.apk --no-source-search
```

## 输出示例

终端输出支持颜色高亮：不合规项以红色/黄色标注，通过以绿色显示。重定向到文件或管道时自动关闭颜色（可通过 `NO_COLOR=1` 环境变量强制关闭）。

### 全部通过

```
================================================================================================================================
 APK 16KB 页面大小对齐检查报告
 文件: app.apk
 大小: 95.79 MB  |  共 25 个 .so 文件  |  通过: 25  |  不合规: 0
================================================================================================================================

 ✅ 通过  所有 25 个共享库均符合 16KB 对齐规范。
```

### 存在不合规项

```
================================================================================================================================
 APK 16KB 页面大小对齐检查报告
 文件: app.apk
 大小: 65.02 MB  |  共 24 个 .so 文件  |  通过: 15  |  不合规: 9
================================================================================================================================

 ❌ 不合规  9 个共享库不符合 16KB 对齐规范。

 序号   SO 文件                              ABI           ELF对齐            ZIP对齐       来源
 ---- ---------------------------------- ------------- ---------------- ----------- ---------------------------------------------
 1    libgifimage.so                     arm64-v8a     4KB              已压缩         com.facebook.fresco:animated-gif:2.5.0
 2    libimagepipeline.so                arm64-v8a     4KB              已压缩         com.facebook.fresco:imagepipeline:2.5.0
                                                                                    com.facebook.fresco:imagepipeline-native:2.5.0
 3    libnative-filters.so               arm64-v8a     4KB              已压缩         com.facebook.fresco:nativeimagefilters:2.5.0
 4    libnative-imagetranscoder.so       arm64-v8a     4KB              已压缩         com.facebook.fresco:nativeimagetranscoder:2.5.0
 5    libdcblur.so                       arm64-v8a     64KB/RELRO异常     已压缩         本地依赖: lib.5plus.base-release.aar
 6    libsecsdk.so                       x86_64        4KB              已压缩         System.loadLibrary 引用
 ...

 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 结论: 9/24 个共享库需要使用 16KB 对齐方式重新编译。
 参考: https://developer.android.com/guide/practices/page-sizes
```

颜色含义（终端中）：
- 🔴 红色：ELF对齐 < 16KB（不合规），或 ZIP 未对齐
- 🟡 黄色：ELF p_align >= 16KB 但存在 RELRO 问题；SO 文件名
- 🟢 绿色：全部通过，或 ZIP 已对齐
- 暗色：表头、分隔线、已压缩状态、未找到来源

来源列说明：
- **精确 Maven 坐标**（如 `com.facebook.fresco:imagepipeline:2.5.0`）：从本地 Gradle/Maven 缓存中反推，或从 APK 内 META-INF 版本文件精确匹配
- **本地依赖路径**（如 `本地依赖: xxx.aar (/path/to/module/libs/xxx.aar)`）：从你手动提供的目录中识别（常见于 `implementation fileTree(...)`）
- **推测坐标**（如 `com.facebook:imagepipeline (推测)`）：无 Gradle 缓存时，从 DEX 字符串池中的 Java 包名推测的 Maven 坐标
- **System.loadLibrary 引用**：在 DEX 中发现了 `System.loadLibrary()` 调用，但无法识别具体依赖
- **未找到**：未能找到相关线索

### 详细模式（`--verbose`）

在默认输出基础上，每条不合规记录额外展示 APK 内路径和所有 ELF PT_LOAD 段详情：

```
 1    libgifimage.so                     arm64-v8a     4KB              已压缩         com.facebook.fresco:animated-gif:2.5.0
      路径: lib/arm64-v8a/libgifimage.so
      LOAD[0]  offset=0x00000000  vaddr=0x00000000  filesz=0x00038D3C  align=4KB (0x1000)  !!
      LOAD[1]  offset=0x000399D0  vaddr=0x0003A9D0  filesz=0x000038B0  align=4KB (0x1000)  !!
```

### JSON 模式（`--json`）

```json
{
  "apk": "app.apk",
  "total_so_files": 24,
  "compliant": 15,
  "non_compliant": 9,
  "is_16kb_compliant": false,
  "details": [
    {
      "path_in_apk": "lib/arm64-v8a/libgifimage.so",
      "abi": "arm64-v8a",
      "so_name": "libgifimage.so",
      "is_compliant": false,
      "elf": {
        "is_aligned": false,
        "min_align": 4096,
        "min_align_display": "4KB",
        "relro_ok": true,
        "relro_issue": "",
        "load_segments": [
          {"offset": 0, "align": 4096, "align_display": "4KB"}
        ]
      },
      "zip": {"is_compressed": true, "data_offset": 1234, "is_aligned": false},
      "sources": ["com.facebook.fresco:animated-gif:2.5.0"]
    }
  ]
}
```

## 来源追溯原理

工具综合使用 **用户指定目录**、**本地依赖缓存** 和 **APK 内容分析** 三种方式追溯 .so 的依赖来源：

### 用户指定目录（最高优先级）

不再自动猜测项目目录。你可以通过 `--search-dir`（可多次指定）或交互输入，明确提供本地 `.aar/.jar` 所在目录。

### Gradle/Maven 缓存（优先）

自动检测 `~/.gradle/caches/modules-2/files-2.1` 和 `~/.m2/repository` 目录，扫描其中的 .aar/.jar 文件，精确匹配包含目标 .so 的 Maven 依赖，并通过 META-INF 版本文件交叉验证筛选正确版本。

### APK 内容分析（回退）

当本地无 Gradle/Maven 缓存时，通过分析 APK 内部文件推测来源：

1. **嵌套归档扫描**: 检查 APK 内嵌套的 .aar/.jar 文件是否包含对应 .so
2. **META-INF 版本文件**: 匹配 `META-INF/<group>_<artifact>.version` 中的 Maven 坐标
3. **DEX 字符串池搜索**: 在 DEX 文件中搜索与 .so 相关的 Java 包名和 `System.loadLibrary()` 引用
4. **APK 文件路径匹配**: 在 APK 内所有文件路径中查找与 .so 名称相关的条目
5. **外部目录扫描**: 如指定 `--search-dir`，在外部目录中搜索包含对应 .so 的 .aar/.jar 文件

## 检查原理

### ELF 对齐（PT_LOAD alignment）

共享库 (.so) 是 ELF 格式文件，PT_LOAD 段的 `p_align` 字段决定内存对齐方式。16KB 页面大小要求所有 PT_LOAD 段的 `p_align >= 16384 (2^14)`。若为 4096 (2^12)，则仅支持 4KB 页面大小。

此外，还会检查 `PT_GNU_RELRO` 段：若 RELRO 结束地址不是 16KB 对齐，则它必须是所属 LOAD 段的后缀；否则也会判为不合规（对应 APK Analyzer 中的 RELRO 16KB 提示）。

### ZIP 对齐（zipalign）

APK 是 ZIP 格式文件。对于未压缩存储的 .so 文件，其数据起始偏移需是 16KB 的整数倍，以便系统直接 mmap 加载。已压缩的 .so 不受此约束（安装时会解压到磁盘）。

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 所有 .so 文件均合规 |
| `1` | 存在不合规的 .so 文件 |

---

## aar_16kb_fixer.py — AAR 修补工具

对已知不合规的 AAR 文件，自动将其中 .so 的 ELF 对齐修补为 16KB，输出新的 AAR 文件。合规规则与 `apk_16kb_checker.py` 完全一致。

### 修补原理

| 问题类型 | 修补方式 |
|---------|---------|
| `p_align < 16KB`，且 `p_offset ≡ p_vaddr (mod 16KB)` 已成立 | 仅修改 `p_align` 字段为 16384 |
| `p_align < 16KB`，且 `p_offset ≡ p_vaddr (mod 16KB)` 不成立 | 在段前插入零填充，同步更新 ELF/Program/Section Header 中所有偏移 |
| `p_align` 已 >= 16KB 但 RELRO 结束位置不满足 16KB 规则 | **无法二进制修补**，需重新链接（见下方说明） |

### 使用方法

```bash
# 基本修补（输出 原文件名_16kb.aar）
python3 aar_16kb_fixer.py path/to/some.aar

# 指定输出路径
python3 aar_16kb_fixer.py some.aar -o fixed.aar

# 仅检查，不实际修改
python3 aar_16kb_fixer.py some.aar --dry-run

# 用重新编译好的 .so 替换 AAR 中对应文件（见下方说明）
python3 aar_16kb_fixer.py some.aar --replace-dir ./new_sos/
```

### --replace-dir：替换重新链接的 .so

当 .so 存在 **RELRO 问题**（二进制修补无法解决）时，需要供应商提供重新编译的 .so 文件，再用此工具替换回 AAR：

**目录结构方式一：按 ABI 子目录组织（只替换指定 ABI）**

```
new_sos/
  arm64-v8a/
    libfoo.so
  armeabi-v7a/
    libfoo.so
```

```bash
python3 aar_16kb_fixer.py some.aar --replace-dir ./new_sos/
```

**目录结构方式二：平铺（替换 AAR 中所有 ABI 下同名 .so）**

```
new_sos/
  libfoo.so
```

```bash
python3 aar_16kb_fixer.py some.aar --replace-dir ./new_sos/
```

**实际示例：**

假设拿到了 `__UNI__448B406/lib/arm64-v8a/libdcblur.so`，目录结构已经是 `lib/<abi>/libdcblur.so`，直接传 `lib` 那一层：

```bash
python3 aar_16kb_fixer.py lib.5plus.base-release.aar \
    --replace-dir '__UNI__448B406/lib' \
    -o lib.5plus.base-release_fixed.aar
```

### 输出示例

```
输入: lib.5plus.base-release.aar
输出: lib.5plus.base-release_16kb.aar

────────────────────────────────────────────────────────────────
  ABI: arm64-v8a
────────────────────────────────────────────────────────────────
  SO 文件                                     原对齐  状态
  ────────────────────────────────────── ──────  ────────────────
  libdcblur.so                             64KB  ✗ p_align 已 16KB，但 RELRO 问题需重新链接
    ⚠ RELRO end=0x12000 非 16KB 对齐且非后缀，需重新链接修复

────────────────────────────────────────────────────────────────
  ABI: armeabi-v7a
────────────────────────────────────────────────────────────────
  SO 文件                                     原对齐  状态
  ────────────────────────────────────── ──────  ────────────────
  libdcblur.so                              4KB  ✓ 已修补 (+4096 字节填充)

════════════════════════════════════════════════════════════════
  共 2 个 SO: 0 已合规, 1 已修补, 1 失败
  ⚠ 1 个 SO 存在 RELRO 问题，需重新链接修复
════════════════════════════════════════════════════════════════
```

### 关于 RELRO 问题

RELRO 段的范围由链接器在链接时根据全局变量布局决定，无法通过修改偏移解决。解决方案：

1. **自有 SO**：在 NDK 编译时添加链接参数：
   ```cmake
   # CMakeLists.txt
   target_link_options(your_lib PRIVATE -Wl,-z,max-page-size=16384)
   ```
   ```makefile
   # Android.mk
   LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
   ```

2. **第三方 AAR**：等待供应商发布支持 16KB 的新版本，或使用 `--replace-dir` 导入供应商提供的重新编译版本。

## License

MIT
