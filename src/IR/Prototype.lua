local Prototype = {}
Prototype.__index = Prototype

--[[
  Lua 5.1 Instruction format (32-bit):
    iABC:  [  B:9  ][ C:9 ][ A:8 ][ OP:6 ]
    iABx:  [     Bx:18    ][ A:8 ][ OP:6 ]
    iAsBx: [    sBx:18    ][ A:8 ][ OP:6 ]  (sBx = Bx - MAXARG_sBx)
]]

local MAXARG_Bx   = 2^18 - 1
local MAXARG_sBx  = math.floor(MAXARG_Bx / 2)

-- Lua 5.1 opcodes
Prototype.OPCODES = {
  [0]  = "MOVE",      -- A B     R(A) := R(B)
  [1]  = "LOADK",     -- A Bx    R(A) := Kst(Bx)
  [2]  = "LOADBOOL",  -- A B C   R(A) := (Bool)B; if C then pc++
  [3]  = "LOADNIL",   -- A B     R(A..B) := nil
  [4]  = "GETUPVAL",  -- A B     R(A) := UpVal[B]
  [5]  = "GETGLOBAL", -- A Bx    R(A) := Gbl[Kst(Bx)]
  [6]  = "GETTABLE",  -- A B C   R(A) := R(B)[RK(C)]
  [7]  = "SETGLOBAL", -- A Bx    Gbl[Kst(Bx)] := R(A)
  [8]  = "SETUPVAL",  -- A B     UpVal[B] := R(A)
  [9]  = "SETTABLE",  -- A B C   R(A)[RK(B)] := RK(C)
  [10] = "NEWTABLE",  -- A B C   R(A) := {} (size = B,C)
  [11] = "SELF",      -- A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]
  [12] = "ADD",
  [13] = "SUB",
  [14] = "MUL",
  [15] = "DIV",
  [16] = "MOD",
  [17] = "POW",
  [18] = "UNM",
  [19] = "NOT",
  [20] = "LEN",
  [21] = "CONCAT",
  [22] = "JMP",       -- sBx     pc += sBx
  [23] = "EQ",        -- A B C   if (RK(B) == RK(C)) ~= A then pc++
  [24] = "LT",
  [25] = "LE",
  [26] = "TEST",      -- A C     if not (R(A) <=> C) then pc++
  [27] = "TESTSET",
  [28] = "CALL",      -- A B C   R(A..A+C-2) := R(A)(R(A+1..A+B-1))
  [29] = "TAILCALL",
  [30] = "RETURN",    -- A B     return R(A..A+B-2)
  [31] = "FORLOOP",
  [32] = "FORPREP",
  [33] = "TFORLOOP",
  [34] = "SETLIST",
  [35] = "CLOSE",
  [36] = "CLOSURE",   -- A Bx    R(A) := closure(Proto[Bx])
  [37] = "VARARG",
}

-- Constant type tags (Lua 5.1 bytecode)
Prototype.KTYPES = {
  NIL     = 0,
  BOOLEAN = 1,
  NUMBER  = 3,
  STRING  = 4,
}

function Prototype.new()
  return setmetatable({
    -- Header info
    source       = "",
    lineDefined  = 0,
    lastLine     = 0,
    numUpvals    = 0,
    numParams    = 0,
    isVararg     = 0,
    maxStack     = 0,
    -- Lists
    instructions = {},  -- array of decoded instruction tables
    constants    = {},  -- array of {type, value}
    protos       = {},  -- array of child Prototype
    upvalues     = {},  -- debug: upvalue names
    locals       = {},  -- debug: local var info
    lines        = {},  -- debug: line info per instruction
  }, Prototype)
end

-- Decode a 32-bit instruction word into a table
function Prototype.decodeInstruction(word)
  local op   = word % 64                          -- bits 0-5
  local a    = math.floor(word / 64)   % 256      -- bits 6-13
  local b    = math.floor(word / 2^23) % 512      -- bits 23-31
  local c    = math.floor(word / 2^14) % 512      -- bits 14-22
  local bx   = math.floor(word / 2^14) % 2^18     -- bits 14-31
  local sbx  = bx - MAXARG_sBx

  return {
    word = word,
    op   = op,
    name = Prototype.OPCODES[op] or ("UNKNOWN_"..op),
    A    = a,
    B    = b,
    C    = c,
    Bx   = bx,
    sBx  = sbx,
  }
end

return Prototype
