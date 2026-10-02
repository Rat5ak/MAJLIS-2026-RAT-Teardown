import "pe"

/* Broader pattern hunts accompanying majlis-case.yar.
   File scans: extract containers before scanning their members.
   Validation results and controls: detection-validation-v2.json. */

rule Majlis_Hunt_Native_Protocol_And_File_Errors : hunt pe
{
    meta:
        description = "Native PE combining the observed polling/transfer schema, file-helper errors and backdoor-related imports"
        author = "Daniel Wade / NadSec"
        date = "2026-10-02"
        scope = "Native implementation hunt"
        reference = "https://github.com/Rat5ak/MAJLIS-2026-RAT-Teardown"
        evidence = "protocol-deep-findings.json: poll.body_evidence, file_transfers; binary-findings.json: commands"
        validation = "Offline YARA 4.5.2 validation; detection-validation-v2.json"
        false_positives = "Software sharing these custom file helpers and protocol fields; review matched strings and code"
    strings:
        $schema_next = "next_data" ascii wide
        $schema_client = "client_id" ascii wide
        $header_client = "ClientID: " ascii wide
        $error_open = "Cannot open file (UTF-16 path unsupported by locale)" ascii wide
        $error_write = "Cannot write to file (UTF-16 path unsupported by locale)" ascii wide
        $error_http = "Invalid HTTP response" ascii wide
    condition:
        filesize < 10MB and pe.is_pe and
        all of ($schema_*) and $header_client and 2 of ($error_*) and
        pe.imports("KERNEL32.dll", "CreateProcessW") and
        (
            pe.imports("GDI32.dll", "BitBlt") or
            pe.imports("KERNEL32.dll", "GetLogicalDrives")
        )
}

rule Majlis_Hunt_FTP_WebDAV_Command_Pipe : hunt script
{
    meta:
        description = "FTP local-shell escape reading a WebDAV UNC through MORE and piping it to CMD"
        author = "Daniel Wade / NadSec"
        date = "2026-10-02"
        scope = "Domain-independent delivery-pattern hunt"
        reference = "https://github.com/Rat5ak/MAJLIS-2026-RAT-Teardown"
        evidence = "chain-notes.json: icon.ico.bin remote_command_prefix, webdav_paths and pipes_more_output_to_cmd"
        validation = "Offline YARA 4.5.2 validation; detection-validation-v2.json"
        false_positives = "Administrative scripts or research material containing the same remote-command pipeline"
    strings:
        // The offset checks below enforce line start, including text-file BOMs.
        // The complete flow must occur on one line; the host and path can vary.
        // Bounded repetitions keep the regex from walking an arbitrary file.
        $webdav_pipe = /[ \t]{0,8}![ \t]{0,8}more[ \t]{1,8}"?\\\\[A-Za-z0-9.-]{1,253}@SSL\\[^\r\n|]{1,512}\|[ \t]{0,8}cmd(\.exe)?([ \t"\r\n]|$)/ ascii wide nocase
    condition:
        filesize < 64KB and $webdav_pipe and
        for any i in (1..#webdav_pipe) :
        (
            @webdav_pipe[i] == 0 or
            (@webdav_pipe[i] == 2 and uint16(0) == 0xfeff) or
            (
                @webdav_pipe[i] == 3 and
                uint8(0) == 0xef and uint8(1) == 0xbb and uint8(2) == 0xbf
            ) or
            (
                @webdav_pipe[i] >= 1 and
                (
                    uint8(@webdav_pipe[i] - 1) == 0x0a or
                    uint8(@webdav_pipe[i] - 1) == 0x0d
                )
            ) or
            (
                @webdav_pipe[i] >= 2 and
                (
                    uint16(@webdav_pipe[i] - 2) == 0x000a or
                    uint16(@webdav_pipe[i] - 2) == 0x000d
                )
            )
        )
}

rule Majlis_Hunt_Recurring_HTTP_Command_Script : hunt script
{
    meta:
        description = "Minute-scheduled task reading commands through MORE plus an echoed HTTP CURL-to-CMD fetcher"
        author = "Daniel Wade / NadSec"
        date = "2026-10-02"
        scope = "Domain, task-name, interval and output-path independent script-pattern hunt"
        reference = "https://github.com/Rat5ak/MAJLIS-2026-RAT-Teardown"
        evidence = "chain-notes.json: res.ico.bin scheduled_task_options, scheduled_task_action_summary and curl_response_to_cmd"
        validation = "Offline YARA 4.5.2 validation; detection-validation-v2.json"
        false_positives = "Administrative automation or documentation reproducing all four command patterns"
    strings:
        $task_create = /schtasks(\.exe)?[ \t]+\/create([ \t"\r\n]|$)/ ascii wide nocase
        $minute_schedule = /\/sc[ \t]+minute([ \t"\r\n]|$)/ ascii wide nocase
        $task_reader = /cmd(\.exe)?[ \t]+\/c[ \t]+more[ \t]+[^\r\n|]{1,256}\|[ \t]{0,8}cmd(\.exe)?([ \t"\r\n]|$)/ ascii wide nocase
        // Includes the escaped pipe and caret-obfuscated CMD seen in the source.
        // Each internal caret is optional; the post-pipe prefix stays bounded.
        $written_fetcher = /echo[ \t]+curl(\.exe)?[ \t]+[^\r\n|]{0,256}https?:\/\/[^\r\n|]{1,512}\|[ \t^]{0,8}c\^?m\^?d(\.exe)?[ \t]{0,8}>/ ascii wide nocase
    condition:
        filesize < 128KB and all of them
}
