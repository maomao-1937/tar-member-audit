"""Generate an owned temporary fixture, run the audit, then remove only that temp."""
import argparse
import gzip
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('scenario', choices=('clean', 'duplicate', 'links', 'truncated', 'compressed', 'long'))
    parser.add_argument('--format', choices=('json', 'text'), default='json')
    args = parser.parse_args()
    output = io.BytesIO()
    names = {'clean': ['folder/a.txt'], 'duplicate': ['a', './a'], 'links': ['shortcut'],
             'truncated': ['a'], 'compressed': ['a'], 'long': ['folder/' + 'x' * 180]}[args.scenario]
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as stream:
        for name in names:
            member = tarfile.TarInfo(name)
            if args.scenario == 'links':
                member.type = tarfile.SYMTYPE
                member.linkname = '../outside'
                stream.addfile(member)
            else:
                member.size = 7
                stream.addfile(member, io.BytesIO(b'example'))
    data = output.getvalue()
    if args.scenario == 'truncated':
        data = data[:520]
    if args.scenario == 'compressed':
        data = gzip.compress(data)
    with tempfile.TemporaryDirectory(prefix='tar-member-audit-demo-') as temporary:
        fixture = Path(temporary) / 'example.tar'
        fixture.write_bytes(data)
        return subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / 'tar_member_audit.py'),
                               str(fixture), '--format', args.format], check=False).returncode


if __name__ == '__main__':
    sys.exit(main())
