local BytecodeParser = require("src.Parser.BytecodeParser")
local VMGen          = require("src.VM.VMGen")

local Pipeline = {}

--[[
  Usage:
    Pipeline.obfuscateFile("input.luac", "output.lua")

  For Luau / Lua 5.1 source files you first need to compile them
  with luac or the Roblox compiler, then feed the bytecode here.
]]

function Pipeline.obfuscateFile(inputPath, outputPath)
  
  local proto = BytecodeParser.fromFile(inputPath)

  local result = VMGen.generate(proto)

  -- Write output
  local f = assert(io.open(outputPath, "w"), "Cannot write: "..outputPath)
  f:write(result)
  f:close()

  print(("[Pipeline] Done: %s -> %s"):format(inputPath, outputPath))
end

function Pipeline.obfuscateBytecode(bytecode)
  local parser = BytecodeParser.new(bytecode)
  local proto  = parser:parse()
  return VMGen.generate(proto)
end

return Pipeline
