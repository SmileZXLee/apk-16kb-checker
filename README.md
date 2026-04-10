# apk-16kb-checker

检测 APK 是否符合 Android 16KB 页面大小对齐规范。

从 Android 15 开始，设备开始支持 16KB 页面大小。自 2025 年 11 月 1 日起，Google Play 要求所有以 Android 15+ 为目标的应用必须支持 16KB 页面大小。此工具帮助你快速检测 APK 中的 .so 文件是否合规，并自动追溯依赖来源。

## 功能

- **ELF 对齐检查**: 解析 .so 文件的 ELF PT_LOAD 段，检查 `p_align` 是否 >= 16384 (2^14)
- **ZIP 对齐检查**: 检查未压缩的 .so 文件在 APK (ZIP) 中的数据偏移是否 16KB 对齐
- **来源追溯**: 通过分析 APK 内所有文件（嵌套归档、META-INF 版本文件、DEX 字符串池、文件路径匹配）自动追溯不合规 .so 的依赖来源，无需依赖 Gradle 或 Maven 环境
- **多种输出格式**: 支持终端表格输出、详细模式（`--verbose`）和 JSON 格式输出（`--json`）
- **纯 Python 实现**: 无需安装 Android SDK 或 NDK，无第三方依赖

## 安装

无需安装，直接使用 Python 3.10+ 运行：

```bash
git clone https://github.com/your-repo/apk-16kb-checker.git
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

# 跳过来源搜索
python3 apk_16kb_checker.py app.apk --no-source-search
```

## 输出示例

### 默认模式

```
====================================================================================================
 APK 16KB 页面大小对齐检查报告
 文件: app.apk
 大小: 65.02 MB  |  共 24 个 .so 文件  |  通过: 15  |  不合规: 9
====================================================================================================

 [不合规] 9 个共享库不符合 16KB 对齐规范。

 序号   SO 文件                              ABI           ELF对齐       ZIP对齐       来源
 ---- ---------------------------------- ------------- ----------- ----------- --------------------------------------
 1    libgifimage.so                     arm64-v8a     2**12       已压缩         System.loadLibrary 引用
 2    libimagepipeline.so                arm64-v8a     2**12       已压缩         com.facebook.imagepipelinebase
                                                                               com.facebook.imagepipeline
 3    libnative-filters.so               arm64-v8a     2**12       已压缩         com.facebook.nativefilters
 4    libnative-imagetranscoder.so       arm64-v8a     2**12       已压缩         com.facebook.nativeimagetranscoder
 5    libsecsdk.so                       x86_64        2**12       已压缩         System.loadLibrary 引用
 ...

 ──────────────────────────────────────────────────────────────────────────────────────────────────
 结论: 9/24 个共享库需要使用 16KB 对齐方式重新编译。
 参考: https://developer.android.com/guide/practices/page-sizes
```

### 详细模式（`--verbose`）

在默认输出基础上，对每条不合规记录额外展示所有 ELF PT_LOAD 段的偏移和对齐信息：

```
 1    libgifimage.so                     arm64-v8a     2**12       已压缩         System.loadLibrary 引用
      LOAD[0]  offset=0x00000000  vaddr=0x00000000  filesz=0x00038D3C  align=2**12  !!
      LOAD[1]  offset=0x000399D0  vaddr=0x0003A9D0  filesz=0x000038B0  align=2**12  !!
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
        "load_segments": [{"offset": 0, "align": 4096}]
      },
      "zip": {"is_compressed": true, "data_offset": 1234, "is_aligned": false},
      "sources": ["System.loadLibrary 引用"]
    }
  ]
}
```

## 来源追溯原理

工具通过遍历 APK 内所有文件来追溯 .so 的依赖来源，无需 Gradle 或 Maven 环境：

1. **嵌套归档扫描**: 检查 APK 内嵌套的 .aar/.jar 文件是否包含对应 .so
2. **META-INF 版本文件**: 匹配 `META-INF/<group>_<artifact>.version` 中的 Maven 坐标
3. **DEX 字符串池搜索**: 在 DEX 文件中搜索与 .so 相关的 Java 包名和 `System.loadLibrary()` 引用
4. **APK 文件路径匹配**: 在 APK 内所有文件路径中查找与 .so 名称相关的条目
5. **外部目录扫描**: 如指定 `--search-dir`，在外部目录中搜索包含对应 .so 的 .aar/.jar 文件

## 检查原理

### ELF 对齐（PT_LOAD alignment）

共享库 (.so) 是 ELF 格式文件，PT_LOAD 段的 `p_align` 字段决定内存对齐方式。16KB 页面大小要求所有 PT_LOAD 段的 `p_align >= 16384 (2^14)`。若为 4096 (2^12)，则仅支持 4KB 页面大小。

### ZIP 对齐（zipalign）

APK 是 ZIP 格式文件。对于未压缩存储的 .so 文件，其数据起始偏移需是 16KB 的整数倍，以便系统直接 mmap 加载。已压缩的 .so 不受此约束（安装时会解压到磁盘）。

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 所有 .so 文件均合规 |
| `1` | 存在不合规的 .so 文件 |

## License

MIT
