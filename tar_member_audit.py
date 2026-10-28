#!/usr/bin/env python3
"""Bounded, nonextracting namespace-policy audit for uncompressed TAR files."""
import argparse
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import unicodedata

MAX_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 1000
MAX_PATH = 4096
MAX_METADATA_RECORDS = 128
MAX_METADATA_BYTES = 256 * 1024
MAX_METADATA_RECORD_BYTES = 64 * 1024
PAX_KEYS = {'path', 'linkpath', 'uname', 'gname', 'uid', 'gid', 'mtime', 'atime', 'ctime', 'hdrcharset'}
EXTENSIONS = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
KINDS = {tarfile.REGTYPE: 'file', tarfile.AREGTYPE: 'file', tarfile.DIRTYPE: 'directory',
         tarfile.SYMTYPE: 'symlink', tarfile.LNKTYPE: 'hardlink', tarfile.CHRTYPE: 'character',
         tarfile.BLKTYPE: 'block', tarfile.FIFOTYPE: 'fifo', tarfile.CONTTYPE: 'contiguous'}
RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])$', re.I)


class AuditError(Exception):
    """Input is outside the supported, bounded physical profile."""


class LiteralPathInfo(tarfile.TarInfo):
    """Keep effective path spelling that tarfile normally trims for extraction."""

    @classmethod
    def frombuf(cls, buf, encoding, errors):
        item = super().frombuf(buf, encoding, errors)
        name = buf[:100].split(b'\0', 1)[0].decode(encoding, errors)
        prefix = buf[345:500].split(b'\0', 1)[0].decode(encoding, errors)
        item.name = prefix + '/' + name if prefix and item.type not in tarfile.GNU_TYPES else name
        item._audit_name = item.name
        return item

    def _apply_pax_info(self, pax_headers, encoding, errors):
        super()._apply_pax_info(pax_headers, encoding, errors)
        if 'path' in pax_headers:
            self.name = pax_headers['path']
        self._audit_name = self.name

    def _proc_builtin(self, stream):
        item = super()._proc_builtin(stream)
        item.name = item._audit_name
        return item

    def _proc_gnulong(self, stream):
        position = stream.fileobj.tell()
        payload = stream.fileobj.read(self.size)
        stream.fileobj.seek(position)
        item = super()._proc_gnulong(stream)
        if self.type == tarfile.GNUTYPE_LONGNAME:
            item.name = payload.split(b'\0', 1)[0].decode(stream.encoding, stream.errors)
        else:
            item.name = item._audit_name
        item._audit_name = item.name
        return item


def rounded(size):
    return (size + 511) // 512 * 512


def validate_pax(payload):
    """Validate framing before tarfile can process extension control data."""
    cursor = 0
    keys = set()
    records = 0
    while cursor < len(payload):
        space = payload.find(b' ', cursor, cursor + 12)
        if space < 0 or not payload[cursor:space].isdigit():
            raise AuditError('Malformed PAX record length')
        length = int(payload[cursor:space])
        end = cursor + length
        if length <= space - cursor + 2 or end > len(payload) or payload[end - 1:end] != b'\n':
            raise AuditError('Malformed PAX record boundary')
        body = payload[space + 1:end - 1]
        if b'=' not in body:
            raise AuditError('Malformed PAX key/value record')
        key_bytes, value_bytes = body.split(b'=', 1)
        try:
            key = key_bytes.decode('ascii')
        except UnicodeError as exc:
            raise AuditError('Unsupported PAX key encoding') from exc
        if key not in PAX_KEYS:
            raise AuditError('Unsupported PAX key (including size or sparse layout controls)')
        value = value_bytes.decode('utf-8', 'surrogateescape')
        if len(value) > MAX_PATH:
            raise AuditError('PAX value exceeds 4096 characters')
        if key in {'uid', 'gid'} and not re.fullmatch(r'[0-9]{1,20}', value):
            raise AuditError('Malformed PAX integer')
        if key in {'mtime', 'atime', 'ctime'} and not re.fullmatch(r'-?[0-9]{1,20}(\.[0-9]{1,20})?', value):
            raise AuditError('Malformed PAX timestamp')
        if key == 'hdrcharset' and value not in {'ISO-IR 10646 2000 UTF-8', 'BINARY'}:
            raise AuditError('Unsupported PAX character set')
        keys.add(key)
        records += 1
        if records > 64:
            raise AuditError('PAX record exceeds 64 keys')
        cursor = end
    return keys


def preflight(data):
    if len(data) % 512:
        raise AuditError('TAR length must be a multiple of 512 bytes; compressed input is unsupported')
    cursor = 0
    logical = 0
    metadata_count = 0
    metadata_bytes = 0
    global_keys = set()
    while cursor + 512 <= len(data):
        block = data[cursor:cursor + 512]
        if block == bytes(512):
            if len(data) - cursor < 1024 or any(data[cursor:]):
                raise AuditError('Require at least 1024 trailing zero bytes; concatenation/nonzero trailing data is unsupported')
            return cursor, logical
        try:
            header = tarfile.TarInfo.frombuf(block, 'utf-8', 'surrogateescape')
        except (tarfile.HeaderError, ValueError, OverflowError) as exc:
            raise AuditError('Invalid TAR header or checksum') from exc
        if header.size < 0 or header.size > MAX_BYTES:
            raise AuditError('Negative or oversized declared member size')
        if header.type not in KINDS and header.type not in EXTENSIONS:
            raise AuditError('Unsupported member layout (including GNU sparse)')
        if header.type in {tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE} and header.size:
            raise AuditError('Unsupported non-file payload layout')
        end = cursor + 512 + rounded(header.size)
        if end > len(data):
            raise AuditError('Truncated declared member data')
        if header.type in EXTENSIONS:
            metadata_count += 1
            metadata_bytes += header.size
            if metadata_count > MAX_METADATA_RECORDS or header.size > MAX_METADATA_RECORD_BYTES or metadata_bytes > MAX_METADATA_BYTES:
                raise AuditError('Metadata processing limit exceeded')
            payload = data[cursor + 512:cursor + 512 + header.size]
            if header.type in {tarfile.XHDTYPE, tarfile.XGLTYPE}:
                keys = validate_pax(payload)
                if header.type == tarfile.XGLTYPE:
                    global_keys.update(keys)
                    if len(global_keys) > 32:
                        raise AuditError('Global PAX key limit exceeded')
            else:
                if len(payload.decode('utf-8', 'surrogateescape').rstrip('\0')) > MAX_PATH:
                    raise AuditError('GNU long name exceeds 4096 characters')
        else:
            logical += 1
            if logical > MAX_MEMBERS:
                raise AuditError('More than 1000 logical members')
        cursor = end
    raise AuditError('Missing physical TAR terminator')


def canonical(name, kind):
    while name.startswith('./'):
        name = name[2:]
    if kind == 'directory' and name.endswith('/'):
        name = name[:-1]
    return name


def portable(name):
    return unicodedata.normalize('NFC', name).casefold()


def policy(members):
    findings = []
    exact = {}
    aliases = {}
    for member in members:
        index, name, kind = member['index'], member['name'], member['kind']
        key = canonical(name, kind)
        parts = key.split('/')
        invalid = (not key or key.startswith('/') or '\\' in key or
                   bool(re.match(r'^[A-Za-z]:', key)) or
                   any(unicodedata.category(char) in {'Cc', 'Cf', 'Cs'} for char in key) or
                   any(part in {'', '.', '..'} for part in parts))
        if invalid:
            findings.append({'code': 'invalid-path', 'indices': [index]})
        if any(part.endswith(('.', ' ')) or RESERVED.fullmatch(part.split('.')[0]) or
               any(char in '<>:"|?*' for char in part) for part in parts):
            findings.append({'code': 'windows-name', 'indices': [index]})
        if kind not in {'file', 'directory'}:
            findings.append({'code': 'unsupported-member-policy', 'indices': [index]})
        exact.setdefault(key, []).append(member)
        aliases.setdefault(portable(key), []).append(member)
    for group in exact.values():
        if len(group) > 1:
            findings.append({'code': 'duplicate-name', 'indices': [item['index'] for item in group]})
    for group in aliases.values():
        if len({canonical(item['name'], item['kind']) for item in group}) > 1:
            findings.append({'code': 'portable-alias', 'indices': [item['index'] for item in group]})
    # Aggregate descendants by conflicting ancestor; retain every origin index.
    for groups, code in ((exact, 'file-prefix'), (aliases, 'portable-file-prefix')):
        conflicts = {}
        for key, children in groups.items():
            pieces = key.split('/')
            for depth in range(1, len(pieces)):
                ancestor = '/'.join(pieces[:depth])
                blockers = [item for item in groups.get(ancestor, []) if item['kind'] != 'directory']
                if blockers:
                    origins = conflicts.setdefault(ancestor, set())
                    origins.update(item['index'] for item in blockers + children)
        findings.extend({'code': code, 'indices': sorted(origins)} for origins in conflicts.values())
    findings.sort(key=lambda item: (item['indices'], item['code']))
    return findings


def audit(path):
    with Path(path).open('rb') as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise AuditError('Input exceeds 16 MiB')
    terminator, logical = preflight(data)
    members = []
    last_end = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:', encoding='utf-8', errors='surrogateescape', tarinfo=LiteralPathInfo) as stream:
        for info in stream:
            if len(members) >= MAX_MEMBERS or len(info.name) > MAX_PATH:
                raise AuditError('Member count or path length limit exceeded')
            if info.sparse is not None or info.type not in KINDS:
                raise AuditError('Unsupported parsed member layout')
            if info.size < 0 or info.size > MAX_BYTES:
                raise AuditError('Invalid parsed member size')
            last_end = info.offset_data + rounded(info.size)
            if last_end > terminator:
                raise AuditError('Member extends past physical terminator')
            members.append({'index': len(members) + 1, 'name': info.name,
                            'kind': KINDS[info.type], 'size': info.size})
    if len(members) != logical or last_end != terminator or len(data) - last_end < 1024 or any(data[last_end:]):
        raise AuditError('Indeterminate physical layout or trailing extension')
    findings = policy(members)
    return {'members': members, 'findings': findings, 'status': 'findings' if findings else 'no-findings'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', help='uncompressed TAR file (maximum 16 MiB)')
    parser.add_argument('--format', choices=('json', 'text'), default='text')
    args = parser.parse_args(argv)
    try:
        report = audit(args.archive)
    except (AuditError, OSError, tarfile.TarError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        # Do not echo parser-controlled names, PAX values, owners or content.
        message = str(exc) if isinstance(exc, AuditError) else type(exc).__name__
        print('Audit error: ' + message, file=sys.stderr)
        return 2
    if args.format == 'json':
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        print('Status: ' + report['status'])
        for item in report['members']:
            print(f"{item['index']}: {item['kind']} {item['size']} {json.dumps(item['name'], ensure_ascii=True)}")
        for finding in report['findings']:
            print(f"{finding['code']}: indices {','.join(map(str, finding['indices']))}")
    return 1 if report['findings'] else 0


def entrypoint():
    try:
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code
        sys.stdout.flush()
        return code
    except (BrokenPipeError, OSError):
        # Replace the broken descriptor so interpreter shutdown cannot exit 120.
        try:
            null = os.open(os.devnull, os.O_WRONLY)
            os.dup2(null, sys.stdout.fileno())
            os.close(null)
        except (OSError, ValueError):
            pass
        try:
            sys.stdout.close()
        except OSError:
            pass
        sys.stdout = open(os.devnull, 'w', encoding='utf-8')
        return 2


if __name__ == '__main__':
    sys.exit(entrypoint())
