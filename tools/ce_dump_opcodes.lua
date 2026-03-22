-- Cheat Engine Lua script: dump L2 opcode tables from memory
--
-- Usage:
-- 1. Open Cheat Engine
-- 2. Attach to L2.exe (File → Open Process)
-- 3. Open Lua Engine (Table → Show Cheat Table Lua Script)
-- 4. Paste this script and press Execute
-- 5. Results saved to D:\tmp\l2_opcodes_ce.json

local OUTPUT = "D:\\tmp\\l2_opcodes_ce.json"

-- Find Core.dll base
local function findModule(name)
  local mods = enumModules()
  for i = 1, #mods do
    if string.lower(mods[i].Name) == string.lower(name) then
      return mods[i].Address
    end
  end
  -- Try known bases
  local known = {["core.dll"] = 0x15000000, ["nwindow.dll"] = 0x10000000, ["engine.dll"] = 0x20000000}
  local kb = known[string.lower(name)]
  if kb then
    local ok, val = pcall(readSmallInteger, kb)
    if ok and val then return kb end
  end
  return nil
end

-- Read null-terminated UTF-16LE string
local function readWStr(addr, maxChars)
  maxChars = maxChars or 128
  local chars = {}
  for i = 0, maxChars - 1 do
    local ch = readSmallInteger(addr + i * 2)
    if ch == nil or ch == 0 then break end
    if ch > 0 and ch < 128 then
      table.insert(chars, string.char(ch))
    else
      table.insert(chars, "?")
    end
  end
  return table.concat(chars)
end

-- Read DWORD
local function readDWORD(addr)
  return readInteger(addr)
end

-- Dump an opcode table
local function dumpTable(base, sizeRVA, nameRVA, label)
  local sizeAddr = base + sizeRVA
  local nameAddr = base + nameRVA

  local tableSize = readDWORD(sizeAddr)
  if tableSize == nil or tableSize == 0 or tableSize > 5000 then
    print(string.format("  %s: bad size %s at 0x%08X", label, tostring(tableSize), sizeAddr))
    return nil, 0
  end

  local tablePtr = readDWORD(nameAddr)
  if tablePtr == nil or tablePtr == 0 then
    print(string.format("  %s: null ptr at 0x%08X", label, nameAddr))
    return nil, 0
  end

  print(string.format("  %s: size=%d, ptr=0x%08X", label, tableSize, tablePtr))

  local opcodes = {}
  local count = 0
  for i = 0, tableSize - 1 do
    local strPtr = readDWORD(tablePtr + i * 4)
    if strPtr ~= nil and strPtr ~= 0 then
      local name = readWStr(strPtr, 64)
      if name and #name >= 2 then
        local key
        if tableSize <= 256 then
          key = string.format("0x%02X", i)
        else
          key = string.format("0x%04X", i)
        end
        opcodes[key] = name
        count = count + 1
      end
    end
  end

  return opcodes, count
end

-- Scan .bss for additional pointer arrays (potential C2S table)
local function scanForTables(base, startRVA, endRVA, knownPtrs)
  local candidates = {}
  print(string.format("  Scanning 0x%08X - 0x%08X for pointer arrays...",
    base + startRVA, base + endRVA))

  for rva = startRVA, endRVA, 4 do
    -- Skip known S2C tables
    local skip = false
    for _, kp in ipairs(knownPtrs) do
      if math.abs(rva - kp) < 8 then skip = true; break end
    end
    if not skip then
      local val = readDWORD(base + rva)
      if val ~= nil and val > 0x10000000 and val < 0x7FFFFFFF then
        -- Check if this points to an array of string pointers
        local valid = 0
        local firstName = nil
        for j = 0, 9 do
          local sp = readDWORD(val + j * 4)
          if sp ~= nil and sp > 0x10000000 and sp < 0x7FFFFFFF then
            local s = readWStr(sp, 32)
            if s and #s >= 2 then
              valid = valid + 1
              if not firstName then firstName = s end
            end
          end
        end
        if valid >= 5 then
          -- Found a table! Dump it fully
          print(string.format("    FOUND TABLE at RVA 0x%08X: ptr=0x%08X first='%s' valid=%d",
            rva, val, firstName or "?", valid))

          local opcodes = {}
          local count = 0
          for i = 0, 511 do
            local sp = readDWORD(val + i * 4)
            if sp == nil or sp == 0 then
              -- Allow gaps
            elseif sp > 0x10000000 and sp < 0x7FFFFFFF then
              local s = readWStr(sp, 64)
              if s and #s >= 2 then
                opcodes[string.format("0x%02X", i)] = s
                count = count + 1
              end
            else
              if i > 10 then break end -- Stop if we hit non-pointer data
            end
          end

          table.insert(candidates, {
            rva = string.format("0x%08X", rva),
            ptr = string.format("0x%08X", val),
            first = firstName,
            count = count,
            opcodes = opcodes
          })
        end
      end
    end
  end

  return candidates
end

-- JSON encode (simple)
local function jsonEncode(obj, indent)
  indent = indent or 0
  local pad = string.rep("  ", indent)
  local pad1 = string.rep("  ", indent + 1)

  if type(obj) == "string" then
    return '"' .. obj:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n') .. '"'
  elseif type(obj) == "number" then
    return tostring(obj)
  elseif type(obj) == "boolean" then
    return tostring(obj)
  elseif type(obj) == "nil" then
    return "null"
  elseif type(obj) == "table" then
    -- Check if array
    local isArray = (#obj > 0)
    if isArray then
      local parts = {}
      for i, v in ipairs(obj) do
        table.insert(parts, pad1 .. jsonEncode(v, indent + 1))
      end
      return "[\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "]"
    else
      local parts = {}
      local keys = {}
      for k in pairs(obj) do table.insert(keys, k) end
      table.sort(keys)
      for _, k in ipairs(keys) do
        table.insert(parts, pad1 .. '"' .. tostring(k) .. '": ' .. jsonEncode(obj[k], indent + 1))
      end
      return "{\n" .. table.concat(parts, ",\n") .. "\n" .. pad .. "}"
    end
  end
  return "null"
end

-- ═══════════════════════════════════════════════
-- MAIN
-- ═══════════════════════════════════════════════
print("═══════════════════════════════════════════")
print("L2 Opcode Table Dumper (Cheat Engine)")
print("═══════════════════════════════════════════")

-- Find Core.dll
local coreBase = findModule("Core.dll")
if not coreBase then
  print("ERROR: Core.dll not found! Make sure L2.exe is opened in CE.")
  return
end
print(string.format("Core.dll base: 0x%08X", coreBase))

-- Known RVAs
local RVA_S2C_SIZE = 0x001DD1D8
local RVA_S2C_NAME = 0x001D7F98
local RVA_S2C_EX_SIZE = 0x001D56B4
local RVA_S2C_EX_NAME = 0x001DBEE0

-- Dump S2C tables
print("\n--- S2C Main Opcodes ---")
local s2cMain, s2cMainCount = dumpTable(coreBase, RVA_S2C_SIZE, RVA_S2C_NAME, "S2C main")

print("\n--- S2C Ex Opcodes ---")
local s2cEx, s2cExCount = dumpTable(coreBase, RVA_S2C_EX_SIZE, RVA_S2C_EX_NAME, "S2C ex")

-- Scan for C2S tables in .bss
print("\n--- Scanning for C2S tables ---")
local knownPtrs = {RVA_S2C_NAME, RVA_S2C_EX_NAME}
local c2sCandidates = scanForTables(coreBase, 0x001D0000, 0x001E5000, knownPtrs)

-- Also scan NWindow.dll .bss
local nwBase = findModule("NWindow.dll")
local nwCandidates = {}
if nwBase then
  print(string.format("\nNWindow.dll base: 0x%08X", nwBase))
  -- NWindow.dll .bss is at high offsets
  nwCandidates = scanForTables(nwBase, 0x01130000, 0x01170000, {})
end

-- Also scan Engine.dll
local engBase = findModule("Engine.dll")
local engCandidates = {}
if engBase then
  print(string.format("\nEngine.dll base: 0x%08X", engBase))
  engCandidates = scanForTables(engBase, 0x01F00000, 0x02000000, {})
end

-- Build result
local result = {
  source = "CheatEngine",
  core_base = string.format("0x%08X", coreBase),
  s2c_main_count = s2cMainCount or 0,
  s2c_main_opcodes = s2cMain or {},
  s2c_ex_count = s2cExCount or 0,
  s2c_ex_opcodes = s2cEx or {},
  c2s_candidates_core = c2sCandidates,
  c2s_candidates_nwindow = nwCandidates,
  c2s_candidates_engine = engCandidates
}

-- Save to file
os.execute("mkdir D:\\tmp 2>nul")
local f = io.open(OUTPUT, "w")
if f then
  f:write(jsonEncode(result))
  f:close()
  print(string.format("\n═══════════════════════════════════════════"))
  print(string.format("SAVED to %s", OUTPUT))
  print(string.format("S2C main: %d opcodes", s2cMainCount or 0))
  print(string.format("S2C ex: %d opcodes", s2cExCount or 0))
  print(string.format("C2S candidates: %d (Core) + %d (NWindow) + %d (Engine)",
    #c2sCandidates, #nwCandidates, #engCandidates))

  -- Show first 5 S2C
  if s2cMain then
    print("\nFirst 5 S2C main:")
    local keys = {}
    for k in pairs(s2cMain) do table.insert(keys, k) end
    table.sort(keys)
    for i = 1, math.min(5, #keys) do
      print(string.format("  %s: %s", keys[i], s2cMain[keys[i]]))
    end
  end

  -- Show C2S candidates
  for _, c in ipairs(c2sCandidates) do
    print(string.format("\nC2S candidate at %s (%d names):", c.rva, c.count))
    local keys = {}
    for k in pairs(c.opcodes) do table.insert(keys, k) end
    table.sort(keys)
    for i = 1, math.min(10, #keys) do
      print(string.format("  %s: %s", keys[i], c.opcodes[keys[i]]))
    end
  end
else
  print("ERROR: Cannot write to " .. OUTPUT)
end

print("\nDone!")
