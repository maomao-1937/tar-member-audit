# Verification record

Local run: 2026-10-28, Windows, CPython 3.11.15, standard library only.
No network, extraction, credentials, or existing user archives were used.

## Actual commands and results

```console
python -m unittest discover -s tests -p test_audit.py -k nested_regular -v
```

Initial RED: 1 test failed because the CLI did not exist (expected exit 0,
observed exit 2). The first complete implementation then exposed an additional
real failure: closed stdout returned Python shutdown code 120. The entrypoint
was fixed to handle help's `SystemExit`, flush output explicitly, and detach a
broken stdout stream. Its focused regression passed with exit 2 for normal and
help output. Directory-spelling regressions also exposed `tarfile`'s slash
trimming; bounded metadata hooks now retain literal effective paths. A raw
directory header is used because the fixture writer normalizes directory names.
PAX BINARY surrogate names and Unicode format controls were each observed RED
before their respective fixes and then passed.

```console
python -m unittest discover -s tests -v
```

Current local suite: **36 test methods passed, 0 failures, 0 errors, 0 skips**.
Methods with subtests exercise additional archive variants; 36 is the unittest
method count, not a claimed count of independent real-world archives.

## Initial hosted CI failure and compatibility repair

The initial Ubuntu run used CPython **3.11.17** and failed the raw directory
empty-component test: a header containing `a//` was reported as `a` with no
finding. The same 34-method revision passed on local CPython 3.11.15. This is a
parser-entry-point difference, not evidence of an OS-specific filesystem issue.
The initial hosted run is [40636264672](https://github.com/maomao-1937/tar-member-audit/actions/runs/40636264672).

Official CPython source comparison identified `_frombuf` and `_fromtarfile`
entry points added in 3.11.17. `_fromtarfile` directly calls `_frombuf`, bypassing
the subclass's original `frombuf` override. The raw name was already trimmed
before the later hook could retain it. GNU/PAX follow-up reads also pass
`dircheck=False` through this internal route.

A new focused regression emulates that direct route on older interpreters. It
first failed locally with expected `a//`, observed `a`; after covering both
header parser entry points it passed. An additional regression uses manually
framed GNU longname and PAX path extensions to verify literal directory names
ending in `//`, because ordinary fixture writers normalize trailing slashes.
The repair keeps the original empty-component test and propagates `dircheck`
unchanged. No tests are skipped or weakened.

After this repair, `python -m unittest discover -s tests -v` passed **36/36**
locally, and `python ci_checks.py` passed all **8/8** documented exit contracts.
These local results alone do not establish that a replacement hosted run passed.

The eight commands in `checks.json` were executed using the current Python:

| Arguments after `python` | Actual exit | Expected exit |
| --- | --- | --- |
| `tar_member_audit.py --help` | 0 | 0 |
| `-m unittest discover -s tests -v` | 0 | 0 |
| `examples/demo.py clean` | 0 | 0 |
| `examples/demo.py duplicate` | 1 | 1 |
| `examples/demo.py links --format text` | 1 | 1 |
| `examples/demo.py truncated` | 2 | 2 |
| `examples/demo.py compressed` | 2 | 2 |
| `examples/demo.py long` | 0 | 0 |

Result: **8/8 exit contracts matched**. The JSON is a list of `{args, exit}`
objects; each `args` list is passed after the Python executable. All example
fixtures are synthetic and live only in freshly owned temporary directories.

## Coverage and boundaries

Tests cover ordinary nested members and empty TARs; exact/canonical duplicates;
repeated directories; file-prefix conflicts in both orders; NFC/case aliases;
links, devices and FIFOs; traversal and portable-name policy; PAX/GNU long paths;
raw/PAX surrogate names; literal directory path components; corrupted checksums
and PAX framing; negative/oversized sizes; truncation, one-block/missing
terminators, concatenation, nonzero trailing bytes and alignment; compressed and
sparse/unknown layouts; archive/member/path/metadata count caps; prohibited PAX
size/sparse controls; redaction of content/link sentinels; and normal/help closed
stdout. Extraction APIs are instrumented to throw if called during a normal audit.

The full archive is bounded in memory, including opaque regular-file payload
bytes; only headers and metadata-extension payloads are interpreted. No native
archive extractor, destination filesystem, production integration, external
archive corpus, benchmark, or sandbox isolation was tested. Local results do not
establish behavior on every Python release or OS. The implementation extends
private `TarInfo` hooks. Regressions cover the legacy `frombuf` route and the
direct `_frombuf` route used from 3.11.17; new interpreter versions still need
their own verification.
Root-managed CI may add separate evidence; it is not claimed by this local record.
