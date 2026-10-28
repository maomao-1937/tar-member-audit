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

Final local suite: **34 test methods passed, 0 failures, 0 errors, 0 skips**.
Methods with subtests exercise additional archive variants; 34 is the unittest
method count, not a claimed count of independent real-world archives.

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
private `TarInfo` hooks, so new interpreter versions need their own verification.
Root-managed CI may add separate evidence; it is not claimed by this local record.
