"""Stage an explicitly supplied standalone package; never generate missing assets.

All extracted bytes remain local. Reports contain only names, sizes and hashes.
The observed public demo manifest is a compatibility check, not an entitlement check.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

EXE_SHA = 'b75ba091fea6425ea9e5e372d2c41bf19f7d3f20a1ff1890130389e9f51f8742'
CORE_SHA = '92d455770a96575e75239b317408d0c5516fbf087d5f28b3a8646e22f06b07bf'
DEMO = {'mxbikes.exe': (3878912, EXE_SHA), 'core.ini': (179, CORE_SHA),
        'joysticks.cfg': (72, None), 'mxbikes.ini': (253, None),
        'proxy_udp.ini': (69, None), 'series.pkz': (1834, None),
        'bikes.pkz': (450147044, None), 'effects.pkz': (16168244, None),
        'misc.pkz': (43752024, None), 'rider.pkz': (105693432, None),
        'tracks.pkz': (1751015009, None), 'tyres.pkz': (20741299, None),
        'ui.pkz': (1178681, None)}
CHUNK = 1024 * 1024


def open_regular(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('not_regular_file')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def stream(source, size, destination=None, hash_required=True):
    h = hashlib.sha256() if hash_required else None
    remaining = size
    while remaining:
        block = source.read(min(CHUNK, remaining))
        if not block:
            raise ValueError('short_asset')
        remaining -= len(block)
        if h is not None:
            h.update(block)
        if destination is not None:
            destination.write(block)
    if source.read(1):
        raise ValueError('oversize_asset')
    return h.hexdigest() if h is not None else None


def inspect_directory(root, manifest=DEMO, hash_all=False):
    rows = []
    for name, (size, expected) in manifest.items():
        row = {'name': name, 'expected_size': size}
        try:
            with open_regular(Path(root) / name) as source:
                actual = os.fstat(source.fileno()).st_size
                row['size'] = actual
                if actual != size:
                    row['status'] = 'size_mismatch'
                else:
                    sha = stream(source, size) if expected or hash_all else None
                    row['sha256'] = sha
                    row['status'] = ('hash_mismatch' if expected and sha != expected
                                     else 'hash_verified' if expected else 'size_verified')
        except FileNotFoundError:
            row['status'] = 'missing'
        except (OSError, ValueError):
            row['status'] = 'unreadable'
        rows.append(row)
    return {'ready': all(r['status'] in ('hash_verified', 'size_verified') for r in rows),
            'files': rows, 'actual_game_asset_reads_verified': False}


def select_members(zf, manifest):
    """Only accept one complete common directory, with no duplicate basenames."""
    found = {}
    names = {name.lower(): name for name in manifest}
    for item in zf.infolist():
        if item.is_dir():
            continue
        raw = item.filename.replace('\\', '/')
        path = PurePosixPath(raw)
        name = names.get(path.name.lower())
        if name is None:
            continue
        if (raw.startswith('/') or ':' in raw or any(x in ('', '.', '..') for x in raw.split('/'))
                or stat.S_ISLNK(item.external_attr >> 16) or item.flag_bits & 1):
            raise ValueError('unsafe_asset_member')
        if name in found:
            raise ValueError('duplicate_asset_member')
        if item.file_size != manifest[name][0]:
            raise ValueError('asset_size_mismatch:' + name)
        found[name] = (item, path.parent)
    if set(found) != set(manifest):
        raise ValueError('missing_assets:' + ','.join(sorted(set(manifest) - set(found))))
    if len({parent for _, parent in found.values()}) != 1:
        raise ValueError('mixed_asset_directories')
    return {name: item for name, (item, _) in found.items()}


def stage_zip(archive, destination, manifest=DEMO):
    """Transactional extraction of only manifest files, with CRC and SHA checks."""
    dest = Path(destination)
    if dest.exists() or dest.is_symlink():
        raise FileExistsError(str(dest))
    if not dest.parent.is_dir():
        raise ValueError('destination_parent_missing')
    with open_regular(archive) as source, zipfile.ZipFile(source) as zf:
        members = select_members(zf, manifest)
        if shutil.disk_usage(dest.parent).free < sum(s for s, _ in manifest.values()):
            raise ValueError('insufficient_disk_space')
        tmp = Path(tempfile.mkdtemp(prefix='.mxb-stage-', dir=dest.parent))
        try:
            for name, (size, expected) in manifest.items():
                with zf.open(members[name]) as src, (tmp / name).open('xb') as out:
                    sha = stream(src, size, out, hash_required=expected is not None)
                if expected is not None and sha != expected:
                    raise ValueError('asset_hash_mismatch:' + name)
            report = inspect_directory(tmp, manifest)
            if not report['ready']:
                raise ValueError('staged_package_invalid')
            if dest.exists() or dest.is_symlink():
                raise FileExistsError(str(dest))
            tmp.rename(dest)
            return report
        finally:
            if tmp.exists():
                shutil.rmtree(tmp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    verify = sub.add_parser('verify'); verify.add_argument('directory', type=Path)
    verify.add_argument('--hash-all', action='store_true')
    stage = sub.add_parser('stage-zip'); stage.add_argument('archive', type=Path)
    stage.add_argument('destination', type=Path)
    args = parser.parse_args()
    report = (inspect_directory(args.directory, hash_all=args.hash_all)
              if args.command == 'verify' else stage_zip(args.archive, args.destination))
    print(json.dumps(report, indent=2))
    return 0 if report['ready'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
