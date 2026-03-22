# Dump L2 opcode tables from running L2.exe via PowerShell
# Must run as Administrator

$ErrorActionPreference = "Stop"
$outFile = "$PSScriptRoot\logs\l2_opcodes_live.json"

# Find L2.exe
$proc = Get-Process -Name "L2" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    @{error="L2.exe not found"} | ConvertTo-Json | Out-File $outFile -Encoding utf8
    Write-Host "L2.exe not found!"
    Read-Host "Press Enter"
    exit 1
}
Write-Host "L2.exe PID: $($proc.Id)"

# Find Core.dll module
$coreMod = $proc.Modules | Where-Object { $_.ModuleName -eq "Core.dll" } | Select-Object -First 1
if (-not $coreMod) {
    @{error="Core.dll not found in L2.exe"} | ConvertTo-Json | Out-File $outFile -Encoding utf8
    Write-Host "Core.dll not found!"
    Read-Host "Press Enter"
    exit 1
}
$coreBase = $coreMod.BaseAddress.ToInt64()
Write-Host "Core.dll base: 0x$($coreBase.ToString('X8')), size: 0x$($coreMod.ModuleMemorySize.ToString('X8'))"

# P/Invoke ReadProcessMemory
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MemReader {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBase, byte[] lpBuffer, int nSize, out int bytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$PROCESS_VM_READ = 0x0010
$PROCESS_QUERY_INFORMATION = 0x0400
$hProc = [MemReader]::OpenProcess($PROCESS_VM_READ -bor $PROCESS_QUERY_INFORMATION, $false, $proc.Id)
if ($hProc -eq [IntPtr]::Zero) {
    @{error="OpenProcess failed"} | ConvertTo-Json | Out-File $outFile -Encoding utf8
    Write-Host "OpenProcess failed!"
    Read-Host "Press Enter"
    exit 1
}

function Read-U32($addr) {
    $buf = New-Object byte[] 4
    $read = 0
    $ok = [MemReader]::ReadProcessMemory($hProc, [IntPtr]$addr, $buf, 4, [ref]$read)
    if (-not $ok) { throw "ReadProcessMemory failed at 0x$($addr.ToString('X8'))" }
    return [BitConverter]::ToUInt32($buf, 0)
}

function Read-WString($addr, $maxChars = 256) {
    if ($addr -eq 0) { return $null }
    $buf = New-Object byte[] ($maxChars * 2)
    $read = 0
    $ok = [MemReader]::ReadProcessMemory($hProc, [IntPtr]$addr, $buf, $buf.Length, [ref]$read)
    if (-not $ok) { return $null }
    # Find null terminator
    for ($i = 0; $i -lt $read - 1; $i += 2) {
        if ($buf[$i] -eq 0 -and $buf[$i+1] -eq 0) {
            return [Text.Encoding]::Unicode.GetString($buf, 0, $i)
        }
    }
    return [Text.Encoding]::Unicode.GetString($buf, 0, $read)
}

# RVAs from PE exports
$tableSizeRVA = 0x001DD1D8
$tableNameRVA = 0x001D7F98
$exTableSizeRVA = 0x001D56B4
$exTableNameRVA = 0x001DBEE0

try {
    # Read table sizes
    $mainSize = Read-U32 ($coreBase + $tableSizeRVA)
    $exSize = Read-U32 ($coreBase + $exTableSizeRVA)
    Write-Host "Main table size: $mainSize, Ex table size: $exSize"

    # Read main table pointer
    $mainPtr = Read-U32 ($coreBase + $tableNameRVA)
    Write-Host "Main table ptr: 0x$($mainPtr.ToString('X8'))"

    $mainOpcodes = @{}
    if ($mainPtr -ne 0 -and $mainSize -gt 0 -and $mainSize -lt 500) {
        # Read pointer array
        $ptrBuf = New-Object byte[] ($mainSize * 4)
        $read = 0
        [MemReader]::ReadProcessMemory($hProc, [IntPtr]$mainPtr, $ptrBuf, $ptrBuf.Length, [ref]$read) | Out-Null

        for ($i = 0; $i -lt $mainSize; $i++) {
            $strPtr = [BitConverter]::ToUInt32($ptrBuf, $i * 4)
            if ($strPtr -ne 0) {
                $name = Read-WString $strPtr 128
                if ($name) {
                    $hex = "0x" + $i.ToString("X2")
                    $mainOpcodes[$hex] = $name
                    Write-Host "  [$hex] = $name"
                }
            }
        }
    }

    # Read ex table pointer
    $exPtr = Read-U32 ($coreBase + $exTableNameRVA)
    Write-Host "Ex table ptr: 0x$($exPtr.ToString('X8'))"

    $exOpcodes = @{}
    if ($exPtr -ne 0 -and $exSize -gt 0 -and $exSize -lt 500) {
        $ptrBuf = New-Object byte[] ($exSize * 4)
        $read = 0
        [MemReader]::ReadProcessMemory($hProc, [IntPtr]$exPtr, $ptrBuf, $ptrBuf.Length, [ref]$read) | Out-Null

        for ($i = 0; $i -lt $exSize; $i++) {
            $strPtr = [BitConverter]::ToUInt32($ptrBuf, $i * 4)
            if ($strPtr -ne 0) {
                $name = Read-WString $strPtr 128
                if ($name) {
                    $hex = "0x" + $i.ToString("X4")
                    $exOpcodes[$hex] = $name
                    Write-Host "  [$hex] = $name"
                }
            }
        }
    }

    # Also read UseKeyCrypt
    $useKeyCrypt = Read-U32 ($coreBase + 0x001D8254)
    Write-Host "GL2UseKeyCrypt: $useKeyCrypt"

    $result = @{
        timestamp = (Get-Date).ToString("o")
        pid = $proc.Id
        core_dll_base = "0x$($coreBase.ToString('X8'))"
        main_count = $mainOpcodes.Count
        main_opcodes = $mainOpcodes
        ex_count = $exOpcodes.Count
        ex_opcodes = $exOpcodes
        GL2UseKeyCrypt = $useKeyCrypt
    }

    $result | ConvertTo-Json -Depth 5 | Out-File $outFile -Encoding utf8
    Write-Host "`nSaved to: $outFile"
    Write-Host "Main opcodes: $($mainOpcodes.Count), Ex opcodes: $($exOpcodes.Count)"
}
finally {
    [MemReader]::CloseHandle($hProc) | Out-Null
}

Read-Host "`nDone! Press Enter to close"
