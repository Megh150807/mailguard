// MailGuard triage rules. meta: category (finding prefix), weight (score), description.
// Add rules here; no code change needed. Heuristics, not malware verdicts.

rule eicar_test_file {
  meta: category = "signature" weight = 100 description = "EICAR anti-malware test string (EICAR)"
  strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition: $a
}

rule embedded_pe {
  meta: category = "embedded-executable" weight = 25 description = "A Windows executable inside another file"
  strings: $dos = "This program cannot be run in DOS mode"
  condition: $dos and not ($dos in (0..512) and uint16(0) == 0x5A4D)
}

rule upx_packed {
  meta: category = "packed" weight = 25 description = "UPX packer marker"
  strings: $a = "UPX!" $b = "UPX0" $c = "UPX1"
  condition: 2 of them
}

rule url {
  meta: category = "url" weight = 5 description = "Contains a URL"
  strings: $a = /https?:\/\/[A-Za-z0-9.\-]{3,253}(:[0-9]{1,5})?(\/[A-Za-z0-9.\/%?=&_\-]*)?/ nocase
  condition: $a
}

rule ip_address {
  meta: category = "ip-address" weight = 5 description = "Contains a literal IPv4 address"
  strings: $a = /[^0-9.][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[^0-9.]/
  condition: $a
}

rule autorun_registry {
  meta: category = "autorun-registry" weight = 20 description = "Windows Run/RunOnce autostart key"
  strings: $a = /\\CurrentVersion\\Run(Once)?/ nocase
  condition: $a
}

rule encoded_powershell {
  meta: category = "encoded-powershell" weight = 25 description = "PowerShell with an encoded command"
  strings: $a = /powershell(\.exe)?( +-[A-Za-z]+( +[A-Za-z0-9]+)?){0,6} +-(e|enc|encodedcommand) +[A-Za-z0-9+\/=]{20}/ nocase
  condition: $a
}

rule hidden_shell {
  meta: category = "hidden-shell" weight = 10 description = "Shell command execution or hidden window"
  strings:
    $a = /cmd(\.exe)?\s+\/c/ nocase
    $b = /-w(indowstyle)?\s+hidden/ nocase
    $c = "/bin/sh -c"
  condition: any of them
}

rule script_host {
  meta: category = "script-host" weight = 25 description = "Windows script host / LOLBin execution"
  strings:
    $a = "WScript.Shell" nocase
    $b = "Shell.Application" nocase
    $c = /CreateObject\s*\(\s*"(WScript|Shell|Scripting)\./ nocase
    $d = /mshta(\.exe)?\s+(https?|vbscript|javascript):/ nocase
    $e = /certutil(\.exe)?\s+[^\n]{0,40}-urlcache/ nocase
    $f = /bitsadmin(\.exe)?\s+\/transfer/ nocase
  condition: any of them
}

rule download_cradle {
  meta: category = "download-cradle" weight = 25 description = "Script that downloads and runs code"
  strings:
    $a = "Net.WebClient" nocase
    $b = "DownloadString" nocase
    $c = "DownloadFile" nocase
    $d = "Invoke-WebRequest" nocase
    $e = "Start-BitsTransfer" nocase
    $f = /\bIEX\b\s*[\(\$]/ nocase
    $g = "Invoke-Expression" nocase
  condition: any of them
}
