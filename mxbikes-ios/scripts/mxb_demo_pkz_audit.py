"""Read-only ZIP/PKZ resource oracle; never extract or modify game assets."""
import hashlib
import json
import stat
import zipfile
from pathlib import Path

MAX_MEMBERS = 100_000
MAX_MEMBER = 64 * 1024 * 1024
FULL_MEMBER_LIMIT = 512 * 1024 * 1024
FULL_ARCHIVE_LIMIT = 8 * 1024 * 1024 * 1024
CHUNK = 64 * 1024


def key(name):
    parts = name.replace('\\', '/').split('/')
    if any(not p or p in ('.', '..') or ':' in p or '\x00' in p or
           p[-1:] in (' ', '.') for p in parts):
        raise ValueError('unsafe_resource_name')
    return '/'.join(parts).casefold()


def index(zf):
    entries = zf.infolist()
    if len(entries) > MAX_MEMBERS:
        raise ValueError('resource_count_limit')
    out = {}
    for item in entries:
        if item.is_dir():
            continue
        name = key(item.filename)
        if name in out:
            raise ValueError('ambiguous_resource_name')
        if item.flag_bits & 1 or stat.S_ISLNK(item.external_attr >> 16):
            raise ValueError('unsupported_resource_type')
        out[name] = item
    return out


def verify(zf, item, max_bytes=MAX_MEMBER):
    if not 0 <= item.file_size <= max_bytes <= FULL_MEMBER_LIMIT:
        raise ValueError('resource_size_limit')
    if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise ValueError('unsupported_compression')
    h = hashlib.sha256()
    count = 0
    with zf.open(item) as source:
        while True:
            block = source.read(min(CHUNK, max_bytes - count + 1))
            if not block:
                break
            count += len(block)
            if count > max_bytes or count > item.file_size:
                raise ValueError('resource_size_limit')
            h.update(block)
    if count != item.file_size:
        raise ValueError('resource_length_mismatch')
    return {'bytes': count, 'sha256': h.hexdigest(), 'crc_verified': True}


def audit(path, max_bytes=MAX_MEMBER, max_samples=3):
    if not 1 <= max_samples <= 16 or not 1 <= max_bytes <= MAX_MEMBER:
        raise ValueError('invalid_audit_budget')
    with zipfile.ZipFile(Path(path), 'r') as zf:
        items = index(zf)
        # One small real member of each supported compression family, then
        # additional smallest nonempty members, bounded independently of ZIP size.
        eligible = sorted((i for i in items.values() if 0 < i.file_size <= max_bytes
                           and i.compress_type in (0, 8)), key=lambda i: (i.file_size, i.filename))
        samples = []
        for kind in (0, 8):
            candidate = next((i for i in eligible if i.compress_type == kind), None)
            if candidate is not None:
                samples.append(candidate)
        samples.extend(i for i in eligible if i not in samples)
        results = [dict(verify(zf, i, max_bytes), compression=i.compress_type)
                   for i in samples[:max_samples]]
        return {'members': len(items), 'sampled_members': len(results),
                'sampled_bytes': sum(r['bytes'] for r in results),
                'samples': results, 'original_engine_reads_verified': False}


def audit_all(path, *, member_limit=FULL_MEMBER_LIMIT, total_limit=FULL_ARCHIVE_LIMIT):
    """Stream every supported member within explicit memory/work limits.
    No member is extracted; the aggregate digest commits to sorted names,
    uncompressed sizes and content hashes without exposing filenames.
    Skipped entries must prevent a complete-integrity claim.
    """
    if not 1 <= member_limit <= FULL_MEMBER_LIMIT or not 1 <= total_limit <= FULL_ARCHIVE_LIMIT:
        raise ValueError('invalid_full_audit_budget')
    total = 0
    verified = 0
    methods = {}
    skipped = {}
    failed = {}
    manifest = hashlib.sha256()
    def bump(d, reason):
        d[reason] = d.get(reason, 0) + 1
    with zipfile.ZipFile(Path(path), 'r') as zf:
        items = index(zf)
        for name, item in sorted(items.items()):
            if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                bump(skipped, 'unsupported_compression')
                continue
            if not 0 <= item.file_size <= member_limit:
                bump(skipped, 'member_limit')
                continue
            if item.file_size > total_limit - total:
                bump(skipped, 'total_limit')
                continue
            # Reserve the budget before attempting decompression, even if CRC
            # verification fails, so malformed entries cannot exceed it.
            total += item.file_size
            try:
                result = verify(zf, item, member_limit)
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, EOFError) as exc:
                bump(failed, type(exc).__name__)
                continue
            record = json.dumps([name, result['bytes'], result['sha256']],
                                ensure_ascii=True, separators=(',', ':')).encode('ascii')
            manifest.update(record + b'\n')
            verified += 1
            bump(methods, str(item.compress_type))
        return {'members': len(items), 'verified_members': verified,
                'verified_bytes': total if not failed else None,
                'attempted_bytes': total, 'compression_methods': methods,
                'skipped': skipped, 'failed': failed,
                'verified_manifest_sha256': manifest.hexdigest(),
                'complete_integrity': verified == len(items) and not skipped and not failed,
                'original_engine_reads_verified': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--all', action='store_true', help='Stream every supported member within bounded budgets')
    args = parser.parse_args()
    print(json.dumps(audit_all(args.archive) if args.all else audit(args.archive), indent=2))
