import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'tar_member_audit.py'


def archive(entries, fmt=tarfile.PAX_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=fmt) as stream:
        for name, kind, data in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.LNKTYPE, tarfile.SYMTYPE):
                item.linkname = 'PRIVATE_LINK_TARGET'
            stream.addfile(item, io.BytesIO(data))
    return output.getvalue()


def regular(*names):
    return archive([(name, tarfile.REGTYPE, b'CONTENT_SENTINEL') for name in names])


class AuditTests(unittest.TestCase):
    def run_bytes(self, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.tar'
            path.write_bytes(data)
            result = subprocess.run([sys.executable, str(CLI), str(path), '--format', 'json'], capture_output=True, text=True, encoding='utf-8')
        return result, json.loads(result.stdout) if result.stdout else {}

    def assert_exit(self, data, code):
        result, report = self.run_bytes(data)
        self.assertEqual(result.returncode, code, result.stderr + result.stdout)
        return report

    def test_nested_regular(self):
        self.assert_exit(archive([('./folder/', tarfile.DIRTYPE, b''), ('folder/a.txt', tarfile.REGTYPE, b'ok')]), 0)

    def test_empty_archive(self):
        self.assert_exit(bytes(1024), 0)

    def test_duplicate_and_origin_indices(self):
        report = self.assert_exit(regular('a', './a'), 1)
        self.assertEqual(report['findings'][0]['indices'], [1, 2])

    def test_duplicate_directories(self):
        self.assert_exit(archive([('a/', tarfile.DIRTYPE, b''), ('./a', tarfile.DIRTYPE, b'')]), 1)

    def test_preserve_directory_empty_components(self):
        for fmt in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
            data = bytearray(archive([('a', tarfile.DIRTYPE, b'')], fmt))
            data[:100] = b'a//' + bytes(97)
            data[148:156] = b'        '
            data[148:156] = ('%06o\0 ' % sum(data[:512])).encode('ascii')
            self.assert_exit(data, 1)

    def test_private_header_parser_route_preserves_raw_directory(self):
        # CPython 3.11.17 routes parsing directly through _frombuf, bypassing
        # subclasses that override only frombuf. Emulate that route on older
        # interpreters too, so this regression stays effective across versions.
        spec = importlib.util.spec_from_file_location('audit_private_route', CLI)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        private_parser = getattr(tarfile.TarInfo, '_frombuf', None)
        base_parser = (private_parser or tarfile.TarInfo.frombuf).__func__

        def header_parser(cls, buf, encoding, errors, *, dircheck=True):
            if private_parser is not None:
                return base_parser(cls, buf, encoding, errors, dircheck=dircheck)
            return base_parser(cls, buf, encoding, errors)

        def direct_route(cls, stream):
            block = stream.fileobj.read(512)
            item = cls._frombuf(block, stream.encoding, stream.errors, dircheck=True)
            item.offset = stream.fileobj.tell() - 512
            return item._proc_member(stream)

        data = bytearray(archive([('a', tarfile.DIRTYPE, b'')], tarfile.USTAR_FORMAT))
        data[:100] = b'a//' + bytes(97)
        data[148:156] = b'        '
        data[148:156] = ('%06o\0 ' % sum(data[:512])).encode('ascii')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'raw.tar'
            path.write_bytes(data)
            with patch.object(tarfile.TarInfo, '_frombuf', classmethod(header_parser), create=True), patch.object(tarfile.TarInfo, 'fromtarfile', classmethod(direct_route)):
                report = module.audit(path)
        self.assertEqual(report['members'][0]['name'], 'a//')
        self.assertEqual(report['status'], 'findings')

    def test_extension_directory_literal_path_spelling(self):
        name = 'd' * 110 + '//'
        member = tarfile.TarInfo('fallback')
        member.type = tarfile.DIRTYPE
        for kind in (tarfile.GNUTYPE_LONGNAME, tarfile.XHDTYPE):
            if kind == tarfile.GNUTYPE_LONGNAME:
                payload = name.encode('utf-8') + b'\0'
            else:
                suffix = (' path=' + name + '\n').encode('utf-8')
                length = len(suffix) + 1
                while len(str(length)) + len(suffix) != length:
                    length = len(str(length)) + len(suffix)
                payload = str(length).encode('ascii') + suffix
            extension = tarfile.TarInfo('extension')
            extension.type = kind
            extension.size = len(payload)
            data = (extension.tobuf(tarfile.GNU_FORMAT) + payload +
                    bytes((-len(payload)) % 512) + member.tobuf(tarfile.USTAR_FORMAT) + bytes(1024))
            with self.subTest(kind=kind):
                report = self.assert_exit(data, 1)
                self.assertEqual(report['members'][0]['name'], name)

    def test_pax_regular_trailing_slash(self):
        self.assert_exit(regular('a' * 150 + '/'), 1)

    def test_surrogate_path_is_policy_finding(self):
        item = tarfile.TarInfo('a')
        header = bytearray(item.tobuf())
        header[0] = 255
        header[148:156] = b'        '
        header[148:156] = ('%06o\0 ' % sum(header)).encode('ascii')
        self.assert_exit(header + bytes(1024), 1)

    def test_pax_binary_surrogate_is_policy_finding(self):
        self.assert_exit(regular('a\udcff'), 1)

    def test_links_specials(self):
        for kind in (tarfile.LNKTYPE, tarfile.SYMTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                self.assert_exit(archive([('x', kind, b'')]), 1)

    def test_prefix_both_orders(self):
        for names in [('a', 'a/b'), ('a/b', 'a')]:
            self.assert_exit(regular(*names), 1)

    def test_portability_aliases(self):
        for names in [('A', 'a'), ('caf\u00e9', 'cafe\u0301'), ('A', 'a/b')]:
            self.assert_exit(regular(*names), 1)

    def test_unsafe_paths(self):
        for name in ('', './', '/', '//host/a', 'C:/a', 'a\\b', 'a/../b', 'a/./b', 'a//b', '../x', 'x\n', 'a/CON.txt', 'a/nul', 'a/COM1.log', 'a/end.', 'a/end ', 'a/\u202ex'):
            with self.subTest(name=name):
                self.assert_exit(regular(name), 1)

    def test_pax_long_path(self):
        self.assert_exit(regular('folder/' + 'a' * 150), 0)

    def test_gnu_long_path(self):
        self.assert_exit(archive([('a' * 180, tarfile.REGTYPE, b'ok')], tarfile.GNU_FORMAT), 0)

    def test_path_cap(self):
        self.assert_exit(regular('a' * 4097), 2)

    def test_member_cap(self):
        self.assert_exit(regular(*(str(n) for n in range(1001))), 2)

    def test_input_cap(self):
        self.assert_exit(bytes(16 * 1024 * 1024 + 1), 2)

    def test_truncated_payload(self):
        self.assert_exit(regular('a')[:520], 2)

    def test_missing_terminator(self):
        self.assert_exit(regular('a')[:1024], 2)

    def test_single_zero_block(self):
        self.assert_exit(regular('a')[:1536], 2)

    def test_bad_checksum(self):
        data = bytearray(regular('a'))
        data[0] ^= 1
        self.assert_exit(data, 2)

    def test_trailing_and_concatenation(self):
        self.assert_exit(regular('a') + regular('b'), 2)
        self.assert_exit(regular('a') + b'x' * 512, 2)

    def test_alignment(self):
        self.assert_exit(regular('a') + b'\0', 2)

    def test_compressed(self):
        import gzip
        self.assert_exit(gzip.compress(regular('a')), 2)

    def test_negative_and_oversized_size(self):
        for size in (-1, 20 * 1024 * 1024):
            item = tarfile.TarInfo('x')
            item.size = size
            self.assert_exit(item.tobuf(tarfile.GNU_FORMAT) + bytes(1024), 2)

    def test_sparse_and_unknown_layout(self):
        for kind in (tarfile.GNUTYPE_SPARSE, b'Z'):
            item = tarfile.TarInfo('x')
            item.type = kind
            self.assert_exit(item.tobuf(tarfile.GNU_FORMAT) + bytes(1024), 2)

    def test_bad_pax(self):
        data = bytearray(regular('a' * 150))
        data[512] = ord('x')
        self.assert_exit(data, 2)

    def test_pax_sparse_and_size_rejected(self):
        for key in ('GNU.sparse.map', 'size'):
            out = io.BytesIO()
            with tarfile.open(fileobj=out, mode='w', pax_headers={key: '0'}) as stream:
                stream.addfile(tarfile.TarInfo('a'))
            self.assert_exit(out.getvalue(), 2)

    def test_metadata_record_cap(self):
        item = tarfile.TarInfo('././@LongLink')
        item.type = tarfile.GNUTYPE_LONGNAME
        item.size = 2
        ext = item.tobuf(tarfile.GNU_FORMAT) + b'a\0' + bytes(510)
        self.assert_exit(ext * 129 + regular('a'), 2)

    def test_global_pax_key_cap(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w', pax_headers={f'key{n}': 'x' for n in range(65)}) as stream:
            stream.addfile(tarfile.TarInfo('a'))
        self.assert_exit(out.getvalue(), 2)

    def test_report_redacts_content_and_link_target(self):
        result, report = self.run_bytes(archive([('a', tarfile.REGTYPE, b'CONTENT_SENTINEL'), ('b', tarfile.SYMTYPE, b'')]))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('CONTENT_SENTINEL', result.stdout + result.stderr)
        self.assertNotIn('PRIVATE_LINK_TARGET', result.stdout + result.stderr)
        self.assertEqual(set(report['members'][0]), {'index', 'name', 'kind', 'size'})

    def test_never_calls_extraction_apis(self):
        spec = importlib.util.spec_from_file_location('audit_under_test', CLI)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.tar'
            path.write_bytes(regular('a'))
            with patch.object(tarfile.TarFile, 'extract', side_effect=AssertionError('extract called')), patch.object(tarfile.TarFile, 'extractall', side_effect=AssertionError('extractall called')), patch.object(tarfile.TarFile, 'extractfile', side_effect=AssertionError('extractfile called')):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main([str(path)]), 0)

    def test_missing_input_and_bad_option(self):
        for args in (['missing.tar'], ['--wrong']):
            result = subprocess.run([sys.executable, str(CLI), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_closed_stdout_normal_and_help(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'input.tar'
            path.write_bytes(regular('a'))
            for args in ([str(path)], ['--help']):
                process = subprocess.Popen([sys.executable, str(CLI), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                process.stdout.close()
                stderr = process.stderr.read()
                process.stderr.close()
                self.assertEqual(process.wait(), 2, stderr)


if __name__ == '__main__':
    unittest.main()
