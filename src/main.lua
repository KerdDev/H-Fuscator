package.path = "./src/?.lua;./src/?/init.lua;" .. package.path

local Pipeline = require("Pipeline")

local input  = arg[1]
local output = arg[2]

if not input then
  print("Usage: lua main.lua <input.luac> [output.lua]")
  os.exit(1)
end

if not output then
  output = input:gsub("%.luac$", ""):gsub("%.lua$", "") .. ".obf.lua"
end

Pipeline.obfuscateFile(input, output)
