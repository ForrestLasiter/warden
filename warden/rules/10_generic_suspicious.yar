/*
   Generic, low-false-positive heuristic rules for common malware shapes.
   These are intentionally conservative starter rules. Add your own or drop
   community rule packs into ~/.warden/rules/.

   NOTE: the command/script rules below are guarded with `filesize < 2MB`.
   These patterns describe *scripts and command lines*, which are tiny. Large
   compiled binaries can contain the same ASCII strings incidentally (e.g. help
   text), which caused false positives on legit signed apps. Scripts stay well
   under the guard, so detection is unaffected while FPs drop sharply.
*/

rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell that downloads and executes code in memory"
        severity    = "high"
        author      = "Warden"
    strings:
        $iex   = "IEX" nocase
        $iex2  = "Invoke-Expression" nocase
        $dl1   = "DownloadString" nocase
        $dl2   = "DownloadData" nocase
        $net   = "Net.WebClient" nocase
    condition:
        filesize < 2MB and ($iex or $iex2) and ($dl1 or $dl2 or $net)
}

rule Encoded_PowerShell_Command
{
    meta:
        description = "PowerShell launched with an encoded/hidden command"
        severity    = "high"
        author      = "Warden"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $hid  = "-w hidden" nocase
        $hid2 = "-windowstyle hidden" nocase
        $nop  = "-nop" nocase
    condition:
        filesize < 2MB and (any of ($enc*) or (2 of ($hid, $hid2, $nop)))
}

rule Certutil_LOLBin_Abuse
{
    meta:
        description = "certutil used to decode/download payloads (living-off-the-land)"
        severity    = "medium"
        author      = "Warden"
    strings:
        $a = "certutil" nocase
        $b = "-decode" nocase
        $c = "-urlcache" nocase
        $d = "-f -split" nocase
    condition:
        filesize < 2MB and $a and ($b or $c or $d)
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Deletes volume shadow copies / backups (ransomware precursor)"
        severity    = "critical"
        author      = "Warden"
    strings:
        $vss1 = "vssadmin delete shadows" nocase
        $vss2 = "vssadmin.exe delete shadows" nocase
        $wmic = "wmic shadowcopy delete" nocase
        $bcd  = "bcdedit /set {default} recoveryenabled no" nocase
        $wba  = "wbadmin delete catalog" nocase
    condition:
        any of them
}

rule Suspicious_Script_Obfuscation_JS
{
    meta:
        description = "JavaScript/HTA obfuscation via eval+unescape / char building"
        severity    = "medium"
        author      = "Warden"
    strings:
        $a = "eval(unescape(" nocase
        $b = "document.write(unescape(" nocase
        $c = "String.fromCharCode(" nocase
        $d = "ActiveXObject(\"WScript.Shell\")" nocase
    condition:
        filesize < 2MB and 2 of them
}
