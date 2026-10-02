import glob
import hashlib
import json
import pathlib
import subprocess
import time
import yara

ROOT = pathlib.Path('/home/kali/majlis-analysis')
OUT = ROOT / 'detection-validation.json'
interfaces = json.loads(subprocess.check_output(['/usr/sbin/ip', '-j', 'link'], text=True))
offline = all('UP' not in i['flags'] for i in interfaces if i['ifname'] != 'lo')
report = {'network_offline': offline, 'sample_execution': False, 'yara_version': yara.__version__, 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
if not offline:
    report['error'] = 'Refused specimen inspection while a non-loopback interface is UP'
    OUT.write_text(json.dumps(report, indent=2))
    raise SystemExit(2)

rules_path = ROOT / 'majlis-case.yar'
report['rules_sha256'] = hashlib.sha256(rules_path.read_bytes()).hexdigest()
rules = yara.compile(filepath=str(rules_path))
report['compile_success'] = True
report['rule_names'] = [rule.identifier for rule in rules]

def scan(path, kind, expected=None):
    path = pathlib.Path(path)
    data = path.read_bytes()
    matches = rules.match(data=data, timeout=30)
    found = sorted(m.rule for m in matches)
    row = {'kind': kind, 'guest_path': str(path), 'filename': path.name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'matches': found}
    if expected is not None:
        row['expected_matches'] = sorted(expected)
        row['matches_expectation'] = found == sorted(expected)
    return row

sample_dir = ROOT / 'extracted/Official Invitation Majilis 2026 Gala Dinner'
exact = 'Majlis_2026_Exact_RAT_Or_Installer'
expected = {
    'Binary.exe': [exact, 'Majlis_2026_RAT_Protocol_And_Capabilities'],
    'Imp_Details.msi.bin': [exact, 'Majlis_2026_Installer_Embedded_Protocol'],
    'Scanned Document 2026.lnk.bin': ['Majlis_2026_FTP_Launching_Shell_Link'],
    'Scanned Image.url': ['Majlis_2026_WebDAV_Internet_Shortcut'],
    'icon.ico.bin': ['Majlis_2026_FTP_Script_WebDAV_Stage'],
    'icon2.xz': [],
    'res.ico.bin': ['Majlis_2026_Task_And_Download_Script'],
}
report['provided_artifacts'] = [scan(path, 'provided', expected.get(path.name)) for path in sorted(sample_dir.iterdir()) if path.is_file()]
report['archive'] = scan(ROOT/'incoming/sample.7z', 'compressed_archive', [])
report['archive_note'] = 'Raw YARA scans do not unpack the 7z archive; extract in a contained environment before scanning members.'

control_paths = [pathlib.Path('/bin/ls'), pathlib.Path('/usr/bin/python3'), pathlib.Path('/etc/os-release'), pathlib.Path('/usr/share/common-licenses/GPL-3')]
pe_patterns = [
    '/usr/lib/python3/dist-packages/pip/_vendor/distlib/*.exe',
    '/usr/lib/python3/dist-packages/distlib/*.exe',
    '/usr/lib/python3/dist-packages/setuptools/*.exe',
    '/usr/share/dotnet/shared/Microsoft.NETCore.App/*/System.Console.dll',
    '/usr/share/dotnet/shared/Microsoft.NETCore.App/*/System.Private.CoreLib.dll',
    '/usr/lib/dotnet/shared/Microsoft.NETCore.App/*/System.Console.dll',
]
pe_candidates = sorted({p for pattern in pe_patterns for p in glob.glob(pattern)})[:12]
control_paths += [pathlib.Path(p) for p in pe_candidates]
report['benign_controls'] = []
for path in control_paths:
    if path.is_file() and path.stat().st_size < 32*1024*1024:
        row = scan(path, 'installed_system_or_package_control', [])
        package = subprocess.run(['/usr/bin/dpkg-query', '-S', str(path)], text=True, capture_output=True)
        row['package_owner'] = package.stdout.strip()[:500] if package.returncode == 0 else None
        row['provenance_limit'] = 'Existing guest-installed file; not independently compared with vendor release hashes.'
        report['benign_controls'].append(row)

# Synthetic near-match cases are strings only, never reconstructed malware.
# They exercise marker conjunctions and file-format gates, not family coverage.
synthetics = {
    'all_protocol_strings_non_PE': b'----Boundary43985743985798fjkfscxWW next_data ClientID: OTP: ',
    'task_source_only': b'MicrosoftUpdates\\updates88679 gomescareerplans.com/docs/',
    'ordinary_internet_shortcut': b'[InternetShortcut]\nURL=https://example.invalid/\n',
    'ftp_marker_without_target': b'!more example.txt |cmd',
    'LNK_marker_strings_without_header': b'\\System32\\ftp.exe -s:icon.ico \\Microsoft\\Edge\\Application\\msedge.exe',
}
report['synthetic_controls'] = []
for name, data in synthetics.items():
    found = sorted(m.rule for m in rules.match(data=data, timeout=30))
    report['synthetic_controls'].append({'name': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'matches': found, 'expected_matches': [], 'matches_expectation': not found})
report['limitations'] = [
    'The positive corpus is one supplied case, not a diverse malware-family corpus.',
    'Negative controls are a small convenience sample, not a false-positive-rate study.',
    'Structural rules may miss changed builds or different string encoding and container layout.',
    'Exact hashes identify bytes only; no execution or runtime behavior is demonstrated by a match.',
    'The supplied JPEG (no malicious content established in this review) intentionally has no positive rule.',
    'Raw scanning does not recursively unpack archives or MSI streams; the tested MSI rule searches its observed raw container bytes.',
]
report['all_expectations_met'] = all(row.get('matches_expectation', True) for group in ['provided_artifacts', 'benign_controls', 'synthetic_controls'] for row in report[group]) and report['archive']['matches_expectation']
OUT.write_text(json.dumps(report, indent=2))
