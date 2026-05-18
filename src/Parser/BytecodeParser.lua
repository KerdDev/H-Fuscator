local Prototype = require("src.IR.Prototype")

local Parser = {}
Parser.__index = Parser

local LUA51_VERSION = 0x51

function Parser.new(bytecode)
  return setmetatable({
    data     = bytecode,
    pos      = 1,
    endian   = "little",
    intSz    = 4,
    sizeSz   = 4,
    insSz    = 4,
    numSz    = 8,
    integral = false,
  }, Parser)
end

-- ── Raw readers ──────────────────────────────────────────────────────────────

function Parser:readByte()
  local b = self.data:byte(self.pos)
  assert(b, "Unexpected end of bytecode at pos "..self.pos)
  self.pos = self.pos + 1
  return b
end

function Parser:readBytes(n)
  local s = self.data:sub(self.pos, self.pos + n - 1)
  self.pos = self.pos + n
  return s
end

function Parser:readUInt32()
  local a = self.data:byte(self.pos)
  local b = self.data:byte(self.pos + 1)
  local c = self.data:byte(self.pos + 2)
  local d = self.data:byte(self.pos + 3)
  assert(a and b and c and d,
    ("readUInt32: out of bounds at pos %d (len=%d)"):format(self.pos, #self.data))
  self.pos = self.pos + 4
  if self.endian == "little" then
    return a + b*256 + c*65536 + d*16777216
  else
    return d + c*256 + b*65536 + a*16777216
  end
end

-- Read a size_t — width depends on sizeSz from header (4 or 8)
function Parser:readSizeT()
  if self.sizeSz == 4 then
    return self:readUInt32()
  else
    -- 8-byte little-endian size_t (64-bit systems)
    -- Lua strings won't exceed 2^32 so we just read lo word
    local lo = self:readUInt32()
    local hi = self:readUInt32()  -- almost always 0, discard
    assert(hi == 0, "String size too large (hi word nonzero)")
    return lo
  end
end

-- Read a platform int (intSz bytes)
function Parser:readInt()
  if self.intSz == 4 then
    return self:readUInt32()
  else
    -- rare: 8-byte int
    local lo = self:readUInt32()
    local _hi = self:readUInt32()
    return lo
  end
end

function Parser:readDouble()
  local bytes = {self.data:byte(self.pos, self.pos + 7)}
  self.pos = self.pos + 8

  if self.endian == "big" then
    local rev = {}
    for i = 1, 8 do rev[i] = bytes[9 - i] end
    bytes = rev
  end

  local sign = math.floor(bytes[8] / 128)
  local exp  = (bytes[8] % 128) * 16 + math.floor(bytes[7] / 16)
  local frac = (bytes[7] % 16) * (2^48)

  for i = 6, 1, -1 do
    frac = frac + bytes[i] * (2^((i-1)*8))
  end

  if exp == 0 and frac == 0 then return 0 end
  if exp == 2047 then
    return frac == 0 and math.huge or (0/0)
  end

  local value = (1 + frac / (2^52)) * (2^(exp - 1023))
  return sign == 1 and -value or value
end

-- Read a Lua string (size_t length prefix + bytes incl. null terminator)
function Parser:readString()
  local sz = self:readSizeT()
  if sz == 0 then return nil end
  local s = self:readBytes(sz)
  -- strip null terminator
  return s:sub(1, -2)
end

-- ── Header ───────────────────────────────────────────────────────────────────

function Parser:parseHeader()
  local b1 = self:readByte()
  local b2 = self:readByte()
  local b3 = self:readByte()
  local b4 = self:readByte()

  if b1 ~= 0x1B or b2 ~= 0x4C or b3 ~= 0x75 or b4 ~= 0x61 then
    error(("Bad signature: 0x%02X 0x%02X 0x%02X 0x%02X"):format(b1,b2,b3,b4))
  end

  local ver = self:readByte()
  if ver ~= LUA51_VERSION then
    error(("Version mismatch: expected 0x51, got 0x%02X"):format(ver))
  end

  local _fmt   = self:readByte()   -- format (0 = official)
  local endian = self:readByte()   -- 1 = little, 0 = big
  self.endian   = (endian == 1) and "little" or "big"
  self.intSz    = self:readByte()  -- size of int
  self.sizeSz   = self:readByte()  -- size of size_t  <-- critical on 64-bit
  self.insSz    = self:readByte()  -- size of instruction (always 4)
  self.numSz    = self:readByte()  -- size of lua_Number
  self.integral = self:readByte() ~= 0

  -- Print header info so we can verify
  print(("[Parser] endian=%s intSz=%d sizeSz=%d insSz=%d numSz=%d")
    :format(self.endian, self.intSz, self.sizeSz, self.insSz, self.numSz))
end

-- ── Prototype ────────────────────────────────────────────────────────────────

function Parser:parseProto()
  local proto = Prototype.new()

  proto.source      = self:readString() or ""
  proto.lineDefined = self:readInt()
  proto.lastLine    = self:readInt()
  proto.numUpvals   = self:readByte()
  proto.numParams   = self:readByte()
  proto.isVararg    = self:readByte()
  proto.maxStack    = self:readByte()

  -- Instructions
  local nInst = self:readInt()
  print(("[Parser] proto '%s': %d instructions"):format(proto.source, nInst))
  for i = 1, nInst do
    local word = self:readUInt32()
    proto.instructions[i] = Prototype.decodeInstruction(word)
  end

  -- Constants
  local nConst = self:readInt()
  print(("[Parser] %d constants"):format(nConst))
  for i = 1, nConst do
    local ktype = self:readByte()
    local val
    if ktype == Prototype.KTYPES.NIL then
      val = nil
    elseif ktype == Prototype.KTYPES.BOOLEAN then
      val = self:readByte() ~= 0
    elseif ktype == Prototype.KTYPES.NUMBER then
      val = self:readDouble()
    elseif ktype == Prototype.KTYPES.STRING then
      val = self:readString()
    else
      error(("Unknown constant type: 0x%02X at pos %d"):format(ktype, self.pos))
    end
    proto.constants[i] = { type = ktype, value = val }
  end

  -- Child prototypes
  local nProto = self:readInt()
  print(("[Parser] %d child protos"):format(nProto))
  for i = 1, nProto do
    proto.protos[i] = self:parseProto()
  end

  -- Debug: line info
  local nLines = self:readInt()
  for i = 1, nLines do
    proto.lines[i] = self:readInt()
  end

  -- Debug: locals
  local nLocals = self:readInt()
  for i = 1, nLocals do
    proto.locals[i] = {
      name    = self:readString(),
      startPC = self:readInt(),
      endPC   = self:readInt(),
    }
  end

  -- Debug: upvalue names
  local nUpvals = self:readInt()
  for i = 1, nUpvals do
    proto.upvalues[i] = self:readString()
  end

  return proto
end

function Parser:parse()
  self:parseHeader()
  return self:parseProto()
end

function Parser.fromFile(path)
  local f, err = io.open(path, "rb")
  if not f then
    error("Cannot open file: "..path.."\n"..(err or ""))
  end
  local data = f:read("*a")
  f:close()
  print(("[Parser] File size: %d bytes"):format(#data))
  return Parser.new(data):parse()
end

return Parser
