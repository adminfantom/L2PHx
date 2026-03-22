# 32-bit PowerShell script to dump L2.exe opcode tables
# Must be run via C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe

$ErrorActionPreference = "Continue"
$outFile = "D:\RABOTKA\Innova\_Reverce_Ingeneering\soft\l2phx_modern\tools\logs\l2_opcodes_live.json"

# Add RPM type
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class MemReader {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr addr, byte[] buf, int size, out int read);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ph, int access, out IntPtr th);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string sys, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr th, bool dis, ref TOKEN_PRIVILEGES tp, int bl, IntPtr pp, IntPtr rl);

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    public static void EnableDebugPrivilege() {
        IntPtr th;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out th);
        long luid;
        LookupPrivilegeValue(null, "SeDebugPrivilege", out luid);
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = 2;
        AdjustTokenPrivileges(th, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(th);
    }

    public static byte[] RPM(IntPtr h, long addr, int size) {
        byte[] buf = new byte[size];
        int read = 0;
        bool ok = ReadProcessMemory(h, new IntPtr(addr), buf, size, out read);
        if (!ok) return null;
        if (read < size) {
            byte[] result = new byte[read];
            Array.Copy(buf, result, read);
            return result;
        }
        return buf;
    }

    public static int ReadInt32(IntPtr h, long addr) {
        byte[] b = RPM(h, addr, 4);
        if (b == null || b.Length < 4) return -1;
        return BitConverter.ToInt32(b, 0);
    }

    public static string ReadWString(IntPtr h, long addr, int maxChars) {
        if (addr == 0) return null;
        byte[] b = RPM(h, addr, maxChars * 2);
        if (b == null) return null;
        for (int i = 0; i < b.Length - 1; i += 2) {
            if (b[i] == 0 && b[i+1] == 0) {
                return System.Text.Encoding.Unicode.GetString(b, 0, i);
            }
        }
        return System.Text.Encoding.Unicode.GetString(b);
    }
}
"@

Write-Host "PowerShell bits: $([IntPtr]::Size * 8)"

# Find L2.exe
$proc = Get-Process -Name "L2" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    Write-Host "L2.exe not found!"
    @{error="L2.exe not found"} | ConvertTo-Json | Set-Content $outFile
    exit 1
}
Write-Host "L2.exe PID: $($proc.Id)"

# List key modules
Write-Host "`nModules:"
$modules = @{}
foreach ($m in $proc.Modules) {
    $name = $m.ModuleName.ToLower()
    if ($name -match "core|engine|nwindow|l2\.exe|windrv") {
        $base = [long]$m.BaseAddress
        Write-Host ("  {0,-20} base=0x{1:X8} size=0x{2:X8}" -f $m.ModuleName, $base, $m.ModuleMemorySize)
        $modules[$name] = @{base=$base; size=$m.ModuleMemorySize}
    }
}

# Enable SeDebugPrivilege
[MemReader]::EnableDebugPrivilege()

# Open process
$PROCESS_VM_READ = 0x0010
$PROCESS_QUERY_INFO = 0x0400
$hp = [MemReader]::OpenProcess($PROCESS_VM_READ -bor $PROCESS_QUERY_INFO, $false, $proc.Id)
if ($hp -eq [IntPtr]::Zero) {
    Write-Host "OpenProcess failed: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    @{error="OpenProcess failed"} | ConvertTo-Json | Set-Content $outFile
    exit 1
}
Write-Host "OpenProcess OK: $hp"

# Find Core.dll base
$coreBase = 0
if ($modules.ContainsKey("core.dll")) {
    $coreBase = $modules["core.dll"].base
} else {
    $coreBase = 0x15000000  # default
}
Write-Host "Core.dll base: 0x$($coreBase.ToString('X8'))"

# Verify MZ header
$sig = [MemReader]::RPM($hp, $coreBase, 2)
if ($sig -ne $null) {
    Write-Host "MZ check: $([BitConverter]::ToString($sig))"
} else {
    Write-Host "Cannot read Core.dll memory!"
    @{error="Cannot read Core.dll"; base="0x$($coreBase.ToString('X8'))"} | ConvertTo-Json | Set-Content $outFile
    [MemReader]::CloseHandle($hp)
    exit 1
}

# RVAs
$RVA = @{
    "GL2UserPacketTableName"   = 0x001D7F98
    "GL2UserPacketTableSize"   = 0x001DD1D8
    "GL2UserExPacketTableName" = 0x001DBEE0
    "GL2UserExPacketTableSize" = 0x001D56B4
    "GL2PacketCheck"           = 0x001DD1C4
    "GL2LastRecvPacketNum"     = 0x001D5674
    "GL2LastSendPacketNum"     = 0x001DD1DC
    "GL2LastRecvPacketNumEX"   = 0x001D7FA4
    "GL2LastSendPacketNumEX"   = 0x001D81E8
}

$result = @{
    timestamp = (Get-Date).ToString("o")
    pid = $proc.Id
    core_base = "0x$($coreBase.ToString('X8'))"
    ps_bits = [IntPtr]::Size * 8
    modules = @{}
}

foreach ($k in $modules.Keys) {
    $result.modules[$k] = "0x$($modules[$k].base.ToString('X8'))"
}

# Read scalar values
Write-Host "`nScalar values:"
foreach ($name in @("GL2PacketCheck","GL2LastRecvPacketNum","GL2LastSendPacketNum","GL2LastRecvPacketNumEX","GL2LastSendPacketNumEX")) {
    $addr = $coreBase + $RVA[$name]
    $val = [MemReader]::ReadInt32($hp, $addr)
    Write-Host ("  {0} = {1} (0x{1:X8})" -f $name, $val)
    $result[$name] = $val
}

# Dump opcode table
function DumpTable($label, $nameRVA, $sizeRVA, $isEx) {
    $sizeAddr = $coreBase + $sizeRVA
    $nameAddr = $coreBase + $nameRVA

    $tblSize = [MemReader]::ReadInt32($hp, $sizeAddr)
    $tblPtr = [MemReader]::ReadInt32($hp, $nameAddr)
    Write-Host ("`n{0}: size={1} ptr=0x{2:X8}" -f $label, $tblSize, $tblPtr)

    if ($tblPtr -eq 0 -or $tblSize -le 0) {
        Write-Host "  Table not initialized"
        return @{}
    }
    if ($tblSize -gt 5000) { $tblSize = 5000 }

    # Read pointer array
    $ptrData = [MemReader]::RPM($hp, [long]$tblPtr, $tblSize * 4)
    if ($ptrData -eq $null) {
        Write-Host "  Cannot read pointer array"
        return @{}
    }

    $opcodes = @{}
    for ($i = 0; $i -lt $tblSize; $i++) {
        $p = [BitConverter]::ToInt32($ptrData, $i * 4)
        if ($p -eq 0) { continue }
        $name = [MemReader]::ReadWString($hp, [long]$p, 128)
        if ($name) {
            $key = if ($isEx) { "0x{0:X4}" -f $i } else { "0x{0:X2}" -f $i }
            $opcodes[$key] = $name
            Write-Host ("    [{0}] {1}" -f $key, $name)
        }
    }
    Write-Host "  Total: $($opcodes.Count) opcodes"
    return $opcodes
}

$mainOps = DumpTable "S2C Main Opcodes" $RVA["GL2UserPacketTableName"] $RVA["GL2UserPacketTableSize"] $false
$exOps = DumpTable "S2C Ex Opcodes" $RVA["GL2UserExPacketTableName"] $RVA["GL2UserExPacketTableSize"] $true

$result["s2c_main_opcodes"] = $mainOps
$result["s2c_main_count"] = $mainOps.Count
$result["s2c_ex_opcodes"] = $exOps
$result["s2c_ex_count"] = $exOps.Count

# Monitor GL2LastSendPacketNum for 5 seconds
Write-Host "`nMonitoring GL2LastSendPacketNum for 5s..."
$sendSamples = @()
$lastVal = -1
for ($i = 0; $i -lt 50; $i++) {
    $v = [MemReader]::ReadInt32($hp, $coreBase + $RVA["GL2LastSendPacketNum"])
    $vEx = [MemReader]::ReadInt32($hp, $coreBase + $RVA["GL2LastSendPacketNumEX"])
    if ($v -ne $lastVal) {
        $ts = (Get-Date).ToString("HH:mm:ss.fff")
        Write-Host "  [$ts] LastSend=0x$($v.ToString('X4')) LastSendEX=0x$($vEx.ToString('X4'))"
        $sendSamples += @{ts=$ts; send=$v; send_hex="0x$($v.ToString('X4'))"; send_ex=$vEx}
        $lastVal = $v
    }
    Start-Sleep -Milliseconds 100
}
$result["c2s_send_samples"] = $sendSamples

[MemReader]::CloseHandle($hp)

$result | ConvertTo-Json -Depth 5 | Set-Content $outFile -Encoding UTF8
Write-Host "`nSaved to: $outFile"
