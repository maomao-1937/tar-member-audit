# tar-member-audit

[![tests](https://github.com/maomao-1937/tar-member-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/tar-member-audit/actions/workflows/tests.yml)

A Python 3.11+ standard-library CLI that reports namespace policy problems in
small **uncompressed TAR archives without extracting anything**. It is useful
when reviewing duplicate names, directory/file clashes, links, and portable
path spelling before choosing how an archive should be handled.

```console
python tar_member_audit.py archive.tar
python tar_member_audit.py archive.tar --format json
python examples/demo.py duplicate
python -m unittest discover -s tests -v
```

The example creates its own temporary archive and removes only its own temporary
directory. It accepts `clean`, `duplicate`, `links`, `truncated`, `compressed`, and
`long`; no downloaded or committed binary fixtures are required.

## Exit codes and output

| Code | Meaning |
| --- | --- |
| 0 | No findings under this tool's policy and supported format profile |
| 1 | One or more namespace/member policy findings |
| 2 | I/O, invalid format, unsupported layout, bound exceeded, or output failure |

JSON contains `status`, `members`, and `findings`. A member exposes only its
one-based `index`, effective `name`, `kind`, and declared `size`. Findings contain
a stable code and every involved origin index. Content, link targets, owners,
and PAX values are excluded from reports. Names are ASCII-escaped in both output
formats, so control characters cannot inject terminal lines. Invalid input emits
a brief error to stderr and no partial success report.

```json
{"code": "duplicate-name", "indices": [1, 2]}
```

`./a` and `a` share a canonical name. A conventional trailing slash is removed
from directory names only. Repeated directories count as duplicates. A file at
`a` conflicts with `a/b` in either archive order. NFC normalization plus Unicode
case folding also detects spelling aliases and file-prefix clashes.

The strict policy flags absolute/UNC/drive paths, backslashes, controls,
surrogates, empty/root names, interior `.`/`..`/empty components, Windows reserved
basenames, trailing dot/space components, and Windows forbidden punctuation.
Symlinks, hardlinks, devices, FIFOs, and contiguous-file types are findings;
targets are never resolved. Multiple codes may refer to the same member set.

## Supported physical profile and limits

- Input is read once with a limit of **16 MiB + 1 byte**, and archives over 16 MiB
  are rejected. At most **1000 logical members**, **4096 characters per effective
  path**, **128 metadata extension records**, **64 KiB per metadata record**, and
  **256 KiB total metadata payload** are accepted.
- A bounded raw header preflight verifies checksums, nonnegative sizes, physical
  offsets and PAX framing before `tarfile` metadata iteration. Each PAX record
  allows at most 64 key/value entries; the global key set is capped at 32 (the
  current allowlist is smaller). Values are capped at 4096 characters.
- Ordinary files/directories, known link/special headers, USTAR names, GNU
  longname/longlink, and PAX `path`/`linkpath` are supported. PAX owner/timestamp
  fields and UTF-8/BINARY `hdrcharset` are accepted within the bounds. Raw binary
  names use UTF-8 with surrogate escaping and are policy findings.
- GNU sparse, unknown member types, unsupported PAX keys (including `size` and
  sparse controls), payload-bearing non-file headers, and indeterminate physical
  layouts return 2. This deliberately rejects some otherwise valid TARs.
- The length must be 512-byte aligned and end with at least **1024 zero bytes**.
  The final member's `offset_data + rounded(size)` must match the physical
  terminator. All remaining bytes must be zero; concatenated archives and nonzero
  trailing bytes return 2. A zero-member TAR with a proper terminator is valid.
- Compressed input is unsupported. GNU/PAX metadata is processed only after its
  size/count/framing limits pass. Recursion and malformed-parser failures return 2.

The code never calls `extract`, `extractall`, or `extractfile`, writes member
paths, or executes archive content. It reads archive bytes into memory and uses
private `TarInfo` parsing hooks to preserve path spelling that Python normally
trims. Both the older `frombuf` metadata route and the direct `_frombuf` route
introduced in CPython 3.11.17 are covered; the latter preserves `dircheck=False`
for GNU/PAX follow-up headers. Compatibility with future Python implementations
needs verification.
These explicit caps reduce work but are **not a universal CPU/memory sandbox**.

An exit code 0 is not a safe-extraction certificate, vulnerability scan, malware
assessment, or complete simulation of every filesystem/extractor. Use a maintained
extractor and the appropriate extraction filters when extraction is actually
needed. See [RESEARCH.md](RESEARCH.md) and [TESTING.md](TESTING.md).

## 中文快速开始

需要 Python 3.11 或更高版本，无第三方依赖。只检查未压缩 `.tar`，不会解包。

```console
python tar_member_audit.py 你的归档.tar --format json
python examples/demo.py clean
python examples/demo.py duplicate
python -m unittest discover -s tests -v
```

退出码：`0` 表示当前策略下未发现问题，`1` 表示路径或成员策略问题，`2` 表示格式、
边界、兼容性或读写错误。报告保留全部成员序号，不展示文件内容、链接目标或所有者。
不支持压缩 TAR、GNU sparse 和超出上述支持范围的扩展头。`0` 不代表可以安全解包。
