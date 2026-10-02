# Majlis detection rules

Ten current rules are split by purpose:

| File | Role |
| --- | --- |
| `majlis-hunt.yar` | Three broader hunts for the native implementation, FTP/WebDAV command pipeline and recurring HTTP command script. These avoid the original domains, hashes, multipart boundary, MSI product GUID and task/file names. |
| `majlis-case.yar` | Seven supplementary known-artifact/case rules. Includes exact SHA-256 identification and case-specific delivery markers. The Shell Link rule checks the HeaderSize and complete fixed CLSID. |

## Scan extracted files

Run in your analysis VM, from this report directory:

```sh
yara -r majlis-hunt.yar /path/to/extracted-files
yara -r majlis-case.yar /path/to/extracted-files
```

The native hunt expects a PE file. Extract an MSI's embedded executable before applying it. YARA does not unpack the supplied 7z automatically. The JPEG deliberately has no positive rule.

Hunt matches need context. The script rules identify command patterns; administrative automation and documentation can contain those patterns. The native rule checks strings and imports in the file, rather than observing runtime activity.

## Validation on 2 October 2026

`detection-validation-v2.json` records YARA 4.5.2 results, rule hashes, sample identities, individual expectations and scan times. Both rule files compile with compiler warnings treated as errors.

- Eight original artifact/archive checks: all expected results.
- 177 clean files: six installed distlib launchers, 165 installed .NET assemblies, four system files and two analyst helper sources; no matches.
- 23 specimen-derived controls and 14 inert synthetic controls: all expected results.
- Changed specimen bytes existed only in guest memory. No specimen was executed.

The controls exercise changed C2/boundary/OTP markers, the native error-message threshold and import alternatives, malformed Shell Link headers, generated benign shortcuts, changed script identifiers, BOM/UTF-16LE handling, comments and incomplete command pipelines. Generated controls are labelled separately from installed clean files. There is one independently collected malware case in this evaluation; no additional malware-family corpus or real clean MSI/LNK collection is represented.

## Reproduce the checks

The harness requires Python with `yara-python`, `pefile` and `pylnk3`, plus Linux `ip`, `findmnt` and `dpkg-query`. It runs in an offline Linux guest and refuses active non-loopback interfaces or mounted VMware shared folders.

From this report directory:

```sh
python3 detection_validate_v2.py --case-root /home/kali/majlis-analysis --rules-dir . --output detection-validation-v2.json
```

Expected guest case layout:

```text
/home/kali/majlis-analysis/
  incoming/sample.7z
  extracted/Official Invitation Majilis 2026 Gala Dinner/
    [the seven supplied artifacts]
```

The harness verifies every required sample against `iocs.json`, checks the installed clean-file groups, scans in-memory variations, and exits nonzero if any assertion, scan or expected result fails. Clean corpus discovery uses installed distlib and .NET runtime paths; an independent machine may have different versions and counts, which are recorded in its output.

The initial seven-rule run is recorded in `detection-validation.json` against its earlier rule hash. Use `detection-validation-v2.json` for the current rule files.
