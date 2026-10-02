import "hash"
import "pe"

/* Case-specific triage rules, 2026-10-01. These identify the supplied build
   and delivery artifacts; they do not establish malware-family attribution.
   A match is an investigation lead, not evidence that a file was executed. */

rule Majlis_2026_Exact_RAT_Or_Installer
{
    meta:
        description = "Exact SHA-256 identification of the supplied RAT and MSI"
        confidence = "exact artifact identity only"
    condition:
        (filesize == 574976 and hash.sha256(0, filesize) == "5d8df4c2d08cff5f1c0de8eab56e47ae543bd5c6d2ef04573f61ebb9fbc65716") or
        (filesize == 633856 and hash.sha256(0, filesize) == "4008c8f9e52d3e6fd7df4a980a9a78f46f2412ba2fda10a38aa92d338767c54c")
}

rule Majlis_2026_RAT_Protocol_And_Capabilities
{
    meta:
        description = "Supplied native RAT protocol markers with process and screen-capture imports"
        confidence = "case-specific structural candidate; broader coverage unproven"
    strings:
        $boundary = "----Boundary43985743985798fjkfscxWW" ascii
        $next = "next_data" ascii
        $client = "ClientID: " ascii
        $otp = "OTP: " ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 2MB and
        all of them and pe.imports("KERNEL32.dll", "CreateProcessW") and
        pe.imports("GDI32.dll", "BitBlt")
}

rule Majlis_2026_Installer_Embedded_Protocol
{
    meta:
        description = "Supplied MSI container identity and embedded RAT protocol markers"
        confidence = "case-specific container candidate"
    strings:
        $product = "{C1B4E779-4A66-405F-9B2C-F8CAD4AE106F}" ascii wide
        $boundary = "----Boundary43985743985798fjkfscxWW" ascii
        $next = "next_data" ascii
    condition:
        uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and
        filesize < 3MB and all of them
}

rule Majlis_2026_Task_And_Download_Script
{
    meta:
        description = "Supplied scheduled-task script using the case command source"
        confidence = "case-specific text artifact"
    strings:
        $task = "MicrosoftUpdates\\updates88679" ascii wide nocase
        $source = "gomescareerplans.com/docs/" ascii wide nocase
        $log = "\\public\\music\\err.log" ascii wide nocase
        $scheduler = "schtasks" ascii wide nocase
    condition:
        filesize < 64KB and all of them
}

rule Majlis_2026_FTP_Script_WebDAV_Stage
{
    meta:
        description = "Supplied FTP shell-escape script referring to the case WebDAV stage"
        confidence = "case-specific text artifact"
    strings:
        $escape = "!more " ascii wide nocase
        $stage = "rappellingaart.com@SSL\\secure-docs\\res.ico" ascii wide nocase
        $shell = "|cmd" ascii wide nocase
    condition:
        filesize < 8KB and all of them
}

rule Majlis_2026_WebDAV_Internet_Shortcut
{
    meta:
        description = "Internet shortcut to the case WebDAV entry path"
        confidence = "case-specific delivery indicator; not proof of code execution"
    strings:
        $format = "[InternetShortcut]" ascii wide nocase
        $target = "file://rappellingaart.com@SSL/secure-docs/3" ascii wide nocase
    condition:
        filesize < 16KB and all of them
}

rule Majlis_2026_FTP_Launching_Shell_Link
{
    meta:
        description = "Supplied Shell Link using FTP script input and the Edge icon"
        confidence = "case-pattern candidate; legitimate administrator links could match"
    strings:
        $ftp = "\\System32\\ftp.exe" ascii wide nocase
        $arg = "-s:icon.ico" ascii wide nocase
        $icon = "\\Microsoft\\Edge\\Application\\msedge.exe" ascii wide nocase
    condition:
        filesize >= 0x4c and filesize < 64KB and
        uint32(0) == 0x4c and uint32(4) == 0x00021401 and
        uint32(8) == 0 and uint32(12) == 0x000000c0 and
        uint32(16) == 0x46000000 and all of them
}
