local VMGen = {}

local function bxor(a, b)
  local r, bit = 0, 1
  while a > 0 or b > 0 do
    if a % 2 ~= b % 2 then r = r + bit end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit = bit * 2
  end
  return r
end

local function xorenc(data, key)
  local o = {}
  local klen = #key
  for i = 1, #data do
    o[i] = string.format("%02x", bxor(data:byte(i), key:byte(((i-1)%klen)+1)))
  end
  return table.concat(o)
end

local function xordec(hex, key)
  local klen = #key
  local i = 0
  return (hex:gsub("%x%x", function(h)
    i = i + 1
    return string.char(bxor(tonumber(h,16), key:byte(((i-1)%klen)+1)))
  end))
end

do
  local raw = ""
  for i=0,255 do raw=raw..string.char(i) end
  local k = "K3yX0R!"
  assert(xordec(xorenc(raw,k),k)==raw, "XOR self-test failed")
end

local _seed = 12345
local function srandom(s) _seed = s end
local function rand(n)
  _seed = (_seed * 1664525 + 1013904223) % (2^32)
  return (_seed % n) + 1
end
local function shuffle(t)
  for i=#t,2,-1 do
    local j=rand(i); t[i],t[j]=t[j],t[i]
  end
  return t
end

local KEYWORDS = {}
for _,k in ipairs({"and","break","do","else","elseif","end","false","for",
  "function","if","in","local","nil","not","or","repeat","return","then",
  "true","until","while","goto"}) do KEYWORDS[k]=true end

local _used = {}
local _ni = 0

local function resetNames() _used={}; _ni=0 end

local H = {"l","I","O","Q","L"}
local T = {"l","I","O","Q","L","x","X","v","V"}

local function genName()
  repeat
    _ni = _ni + 1
    local n = _ni - 1
    local h = H[(n % #H)+1]; n = math.floor(n / #H)
    local t1 = T[(n % #T)+1]; n = math.floor(n / #T)
    local t2 = T[(n % #T)+1]
    local name = h..t1..t2
    if not KEYWORDS[name] and not _used[name] then
      _used[name]=true; return name
    end
  until false
end

-- ── Binary packer ────────────────────────────────────────────────────────────

local function pu32(t, v)
  v = math.floor(v) % (2^32)
  t[#t+1]=string.char(v%256)
  t[#t+1]=string.char(math.floor(v/256)%256)
  t[#t+1]=string.char(math.floor(v/65536)%256)
  t[#t+1]=string.char(math.floor(v/16777216)%256)
end

local function pdbl(t, num)
  if num==0 or num~=num then for i=1,8 do t[#t+1]="\0" end; return end
  local sign=0
  if num<0 then sign=1; num=-num end
  if num==math.huge then
    t[#t+1]="\0";t[#t+1]="\0";t[#t+1]="\0";t[#t+1]="\0"
    t[#t+1]="\0";t[#t+1]="\0";t[#t+1]="\240"
    t[#t+1]=string.char(127+sign*128); return
  end
  local exp=0; local frac=num
  while frac>=2 do frac=frac/2; exp=exp+1 end
  while frac<1  do frac=frac*2; exp=exp-1 end
  frac=frac-1; exp=exp+1023
  local m=frac*(2^52)
  local bytes={}
  for i=1,6 do bytes[i]=m%256; m=math.floor(m/256) end
  bytes[7]=(m%16)+(exp%16)*16
  bytes[8]=math.floor(exp/16)+sign*128
  for i=1,8 do t[#t+1]=string.char(bytes[i]) end
end

local function pstr(t, s)
  if s==nil then pu32(t,0); return end
  pu32(t,#s); t[#t+1]=s
end

-- ── Opcode map ───────────────────────────────────────────────────────────────

local REAL_OPS = {
  MOVE=0,LOADK=1,LOADBOOL=2,LOADNIL=3,GETUPVAL=4,
  GETGLOBAL=5,GETTABLE=6,SETGLOBAL=7,SETUPVAL=8,SETTABLE=9,
  NEWTABLE=10,SELF=11,ADD=12,SUB=13,MUL=14,DIV=15,MOD=16,
  POW=17,UNM=18,NOT=19,LEN=20,CONCAT=21,JMP=22,EQ=23,LT=24,
  LE=25,TEST=26,TESTSET=27,CALL=28,TAILCALL=29,RETURN=30,
  FORLOOP=31,FORPREP=32,TFORLOOP=33,SETLIST=34,CLOSE=35,
  CLOSURE=36,VARARG=37,
}

local function buildOpcodeMap()
  -- Build pool 0..255, shuffle it
  local pool={}
  for i=0,255 do pool[i+1]=i end
  shuffle(pool)
  local enc={} -- enc[real]=encoded
  local dec={} -- dec[encoded]=real
  local i=0
  for _,real in pairs(REAL_OPS) do
    enc[real]=pool[i+1]
    dec[pool[i+1]]=real
    i=i+1
  end
  return enc,dec
end

-- ── Pack proto ───────────────────────────────────────────────────────────────

local CT_NIL=0; local CT_BOOL=1; local CT_NUM=2; local CT_STR=3

local function packProto(p, t, encMap)
  t[#t+1]=string.char(p.numParams)
  t[#t+1]=string.char(p.isVararg)
  t[#t+1]=string.char(p.maxStack)
  t[#t+1]=string.char(p.numUpvals)
  pu32(t,#p.instructions)
  for _,inst in ipairs(p.instructions) do
    t[#t+1]=string.char(encMap[inst.op] or inst.op)
    t[#t+1]=string.char(inst.A)
    pu32(t,inst.B); pu32(t,inst.C)
    pu32(t,inst.Bx); pu32(t,inst.sBx+131071)
  end
  pu32(t,#p.constants)
  for _,k in ipairs(p.constants) do
    if k.type==0 then t[#t+1]=string.char(CT_NIL)
    elseif k.type==1 then
      t[#t+1]=string.char(CT_BOOL)
      t[#t+1]=string.char(k.value and 1 or 0)
    elseif k.type==3 then t[#t+1]=string.char(CT_NUM); pdbl(t,k.value)
    elseif k.type==4 then t[#t+1]=string.char(CT_STR); pstr(t,k.value)
    end
  end
  pu32(t,#p.protos)
  for _,child in ipairs(p.protos) do packProto(child,t,encMap) end
end

local function encodeProto(p, key, encMap)
  local t={}; packProto(p,t,encMap)
  local raw=table.concat(t)
  local enc=xorenc(raw,key)
  assert(xordec(enc,key)==raw,"encode roundtrip failed")
  return enc
end

-- ── VM Generator ─────────────────────────────────────────────────────────────

function VMGen.generate(proto)
  srandom(os.time())
  resetNames()

  local KEY="X"..tostring(rand(9999)).."Q"..tostring(rand(9999))
  local encMap,decMap=buildOpcodeMap()
  local encoded=encodeProto(proto,KEY,encMap)

  local function N() return genName() end

  -- All variable names
  local nDEC=N(); local nD=N(); local nPOS=N()
  local nRB=N();  local nRU=N(); local nRS=N(); local nRDB=N()
  local nDP=N();  local nUNP=N(); local nPKK=N()
  local nGFN=N(); local nRK=N(); local nX=N(); local nDISP=N()
  -- temps (re-declared local in each scope, safe)
  local nTA=N(); local nTB=N(); local nTC=N(); local nTD=N()
  local nTE=N(); local nTF=N(); local nTG=N(); local nBIT=N()
  -- executor
  local nPR=N();  local nUV=N();  local nRG=N();  local nKK=N()
  local nCD=N();  local nPP=N();  local nPC=N();  local nVA=N()
  local nVS=N();  local nINST=N(); local nOP=N()
  local nAA=N();  local nBB=N();  local nCC=N()
  local nBX=N();  local nSBX=N()
  local nFN=N();  local nARG=N(); local nRES=N(); local nRET=N()
  local nCH=N();  local nCU=N();  local nPS=N()
  local nOBJ=N(); local nTMP=N(); local nBASE=N(); local nLI=N()
  local nH=N();   local nBY=N();  local nSG=N();  local nEX=N()
  local nFR=N()
  -- dynamic field names for instruction struct
  local fOP=N(); local fA=N(); local fB=N()
  local fC=N();  local fBX=N(); local fSBX=N()
  -- dynamic field names for proto struct
  local pNP=N(); local pVA=N(); local pMS=N(); local pNU=N()
  local pI=N();  local pK=N();  local pP=N()
  -- dp locals
  local nNP2=N(); local nVF2=N(); local nMS2=N(); local nNU2=N()
  local nNI=N();  local nINS2=N(); local nNK=N(); local nKKT=N()
  local nNPP=N(); local nPPT=N(); local nTYP=N()

  local L={}
  local function w(s) L[#L+1]=s end

  -- XOR decoder
  w(("local function %s(%s,%s);"):format(nDEC,nTA,nTB))
  w(("local %s=0;"):format(nLI))
  w(("return(%s:gsub('%%x%%x',function(%s);"):format(nTA,nH))
  w(("%s=%s+1;"):format(nLI,nLI))
  w(("local %s=tonumber(%s,16);"):format(nTC,nH))
  w(("local %s=%s:byte(((%s-1)%%%s(%s))+1);"):format(nTD,nTB,nLI,"#",nTB))
  w(("local %s,%s,%s,%s=0,1,%s,%s;"):format(nTE,nBIT,nTF,nTG,nTC,nTD))
  w(("while %s>0 or %s>0 do;"):format(nTF,nTG))
  w(("if %s%%2~=%s%%2 then %s=%s+%s;end;"):format(nTF,nTG,nTE,nTE,nBIT))
  w(("%s=math.floor(%s/2);"):format(nTF,nTF))
  w(("%s=math.floor(%s/2);"):format(nTG,nTG))
  w(("%s=%s*2;"):format(nBIT,nBIT))
  w("end;")
  w(("return string.char(%s%%256);"):format(nTE))
  w("end));")
  w("end;")

  w(("local %s=%s('%s','%s');"):format(nD,nDEC,encoded,KEY))
  w(("local %s=1;"):format(nPOS))

  -- Readers
  w(("local function %s();local %s=%s:byte(%s);%s=%s+1;return %s;end;"):format(nRB,nTA,nD,nPOS,nPOS,nPOS,nTA))

  w(("local function %s();"):format(nRU))
  w(("local %s,%s,%s,%s=%s:byte(%s,%s+3);%s=%s+4;"):format(nTA,nTB,nTC,nTD,nD,nPOS,nPOS,nPOS,nPOS))
  w(("return %s+%s*256+%s*65536+%s*16777216;end;"):format(nTA,nTB,nTC,nTD))

  w(("local function %s();"):format(nRS))
  w(("local %s=%s();if %s==0 then return nil;end;"):format(nTA,nRU,nTA))
  w(("local %s=%s:sub(%s,%s+%s-1);%s=%s+%s;return %s;end;"):format(nTB,nD,nPOS,nPOS,nTA,nPOS,nPOS,nTA,nTB))

  w(("local function %s();"):format(nRDB))
  w(("local %s={%s:byte(%s,%s+7)};%s=%s+8;"):format(nBY,nD,nPOS,nPOS,nPOS,nPOS))
  w(("local %s=math.floor(%s[8]/128);"):format(nSG,nBY))
  w(("local %s=(%s[8]%%128)*16+math.floor(%s[7]/16);"):format(nEX,nBY,nBY))
  w(("local %s=(%s[7]%%16)*(2^48);"):format(nFR,nBY))
  w(("for %s=6,1,-1 do %s=%s+%s[%s]*(2^((%s-1)*8));end;"):format(nLI,nFR,nFR,nBY,nLI,nLI))
  w(("if %s==0 and %s==0 then return 0;end;"):format(nEX,nFR))
  w(("if %s==2047 then return %s==0 and math.huge or 0/0;end;"):format(nEX,nFR))
  w(("return(%s==1 and -1 or 1)*(1+%s*(2^-52))*(2^(%s-1023));end;"):format(nSG,nFR,nEX))

  -- Proto deserializer
  w(("local %s;"):format(nDP))
  w(("%s=function();"):format(nDP))
  w(("local %s,%s,%s,%s=%s(),%s(),%s(),%s();"):format(nNP2,nVF2,nMS2,nNU2,nRB,nRB,nRB,nRB))
  w(("local %s=%s();local %s={};"):format(nNI,nRU,nINS2))
  w(("for %s=1,%s do;"):format(nLI,nNI))
  w(("local %s=%s();local %s=%s();"):format(nTA,nRB,nTB,nRB))
  w(("local %s,%s,%s,%s=%s(),%s(),%s(),%s()-131071;"):format(nTC,nTD,nTE,nTF,nRU,nRU,nRU,nRU))
  w(("%s[%s]={%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s};"):format(
    nINS2,nLI,fOP,nTA,fA,nTB,fB,nTC,fC,nTD,fBX,nTE,fSBX,nTF))
  w("end;")
  w(("local %s=%s();local %s={};"):format(nNK,nRU,nKKT))
  w(("for %s=1,%s do;"):format(nLI,nNK))
  w(("local %s=%s();"):format(nTYP,nRB))
  w(("if %s==0 then %s[%s]=nil;"):format(nTYP,nKKT,nLI))
  w(("elseif %s==1 then %s[%s]=%s()~=0;"):format(nTYP,nKKT,nLI,nRB))
  w(("elseif %s==2 then %s[%s]=%s();"):format(nTYP,nKKT,nLI,nRDB))
  w(("elseif %s==3 then %s[%s]=%s();end;"):format(nTYP,nKKT,nLI,nRS))
  w("end;")
  w(("local %s=%s();local %s={};"):format(nNPP,nRU,nPPT))
  w(("for %s=1,%s do %s[%s]=%s();end;"):format(nLI,nNPP,nPPT,nLI,nDP))
  w(("return{%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s,%s=%s};"):format(
    pNP,nNP2,pVA,nVF2,pMS,nMS2,pNU,nNU2,pI,nINS2,pK,nKKT,pP,nPPT))
  w("end;")

  -- Compat
  w(("local %s=table.unpack or unpack;"):format(nUNP))
  w(("local function %s(...) local %s={...};%s.n=select('#',...);return %s;end;"):format(nPKK,nTA,nTA,nTA))
  w(("local %s=type(getfenv)=='function' and getfenv() or _G or {};"):format(nGFN))
  w(("local function %s(%s,%s,%s);if %s>=256 then return %s[%s-255];else return %s[%s];end;end;"):format(
    nRK,nRG,nKK,nLI,nLI,nKK,nLI,nRG,nLI))

  -- Dispatch table: maps encoded_op -> real_op
  local dp={}
  for enc,real in pairs(decMap) do
    dp[#dp+1]=string.format("[%d]=%d",enc,real)
  end
  w(("local %s={%s};"):format(nDISP,table.concat(dp,",")))

  -- Dead code functions (called nowhere, just confuse reversers)
  -- These are separate functions, not inside the dispatch chain
  local nDEAD1=N(); local nDEAD2=N(); local nDEAD3=N()
  w(("local function %s(%s,%s);"):format(nDEAD1,nTA,nTB))
  w(("local %s=%s[%s]+%s[%s+1];"):format(nTC,nTA,nTB,nTA,nTB))
  w(("for %s=1,%s do %s=%s*%s;end;"):format(nLI,nTB,nTC,nTC,nTA))
  w(("return %s;end;"):format(nTC))

  w(("local function %s(%s,%s,%s);"):format(nDEAD2,nTA,nTB,nTC))
  w(("if %s>%s then return %s(%s,%s-%s);end;"):format(nTB,nTC,nDEAD1,nTA,nTB,nTA))
  w(("return %s[%s];end;"):format(nTB,nTA))

  w(("local function %s(%s);"):format(nDEAD3,nTA))
  w(("local %s=%s(%s,2);"):format(nTB,nDEAD1,nTA))
  w(("return %s(%s,%s,%s);end;"):format(nDEAD2,nTA,nTB,nTA))

  -- Executor
  w(("local function %s(%s,%s,...);"):format(nX,nPR,nUV))
  w(("local %s={};"):format(nRG))
  w(("local %s=%s.%s;"):format(nKK,nPR,pK))
  w(("local %s=%s.%s;"):format(nCD,nPR,pI))
  w(("local %s=%s.%s;"):format(nPP,nPR,pP))
  w(("local %s=1;"):format(nPC))
  w(("local %s={...};"):format(nVA))
  w(("for %s=1,%s.%s do %s[%s-1]=%s[%s];end;"):format(nLI,nPR,pNP,nRG,nLI,nVA,nLI))
  w(("local %s=%s.%s;"):format(nVS,nPR,pNP))
  w("while true do;")
  w(("local %s=%s[%s];%s=%s+1;"):format(nINST,nCD,nPC,nPC,nPC))
  w(("local %s=%s[%s.%s];"):format(nOP,nDISP,nINST,fOP))
  w(("local %s=%s.%s;"):format(nAA,nINST,fA))
  w(("local %s=%s.%s;"):format(nBB,nINST,fB))
  w(("local %s=%s.%s;"):format(nCC,nINST,fC))
  w(("local %s=%s.%s;"):format(nBX,nINST,fBX))
  w(("local %s=%s.%s;"):format(nSBX,nINST,fSBX))

  -- Opcode dispatch (clean if/elseif, no dead code inside)
  w(("if %s==0 then %s[%s]=%s[%s];"):format(nOP,nRG,nAA,nRG,nBB))
  w(("elseif %s==1 then %s[%s]=%s[%s+1];"):format(nOP,nRG,nAA,nKK,nBX))
  w(("elseif %s==2 then %s[%s]=(%s~=0);if %s~=0 then %s=%s+1;end;"):format(nOP,nRG,nAA,nBB,nCC,nPC,nPC))
  w(("elseif %s==3 then for %s=%s,%s do %s[%s]=nil;end;"):format(nOP,nLI,nAA,nBB,nRG,nLI))
  w(("elseif %s==4 then %s[%s]=%s[%s+1];"):format(nOP,nRG,nAA,nUV,nBB))
  w(("elseif %s==5 then %s[%s]=%s[%s[%s+1]];"):format(nOP,nRG,nAA,nGFN,nKK,nBX))
  w(("elseif %s==6 then %s[%s]=%s[%s][%s(%s,%s,%s)];"):format(nOP,nRG,nAA,nRG,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==7 then %s[%s[%s+1]]=%s[%s];"):format(nOP,nGFN,nKK,nBX,nRG,nAA))
  w(("elseif %s==8 then %s[%s+1]=%s[%s];"):format(nOP,nUV,nBB,nRG,nAA))
  w(("elseif %s==9 then %s[%s][%s(%s,%s,%s)]=%s(%s,%s,%s);"):format(
    nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==10 then %s[%s]={};"):format(nOP,nRG,nAA))
  w(("elseif %s==11 then local %s=%s[%s];%s[%s+1]=%s;%s[%s]=%s[%s(%s,%s,%s)];"):format(
    nOP,nOBJ,nRG,nBB,nRG,nAA,nOBJ,nRG,nAA,nOBJ,nRK,nRG,nKK,nCC))
  w(("elseif %s==12 then %s[%s]=%s(%s,%s,%s)+%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==13 then %s[%s]=%s(%s,%s,%s)-%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==14 then %s[%s]=%s(%s,%s,%s)*%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==15 then %s[%s]=%s(%s,%s,%s)/%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==16 then %s[%s]=%s(%s,%s,%s)%%%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==17 then %s[%s]=%s(%s,%s,%s)^%s(%s,%s,%s);"):format(nOP,nRG,nAA,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC))
  w(("elseif %s==18 then %s[%s]=-%s[%s];"):format(nOP,nRG,nAA,nRG,nBB))
  w(("elseif %s==19 then %s[%s]=not %s[%s];"):format(nOP,nRG,nAA,nRG,nBB))
  w(("elseif %s==20 then %s[%s]=#%s[%s];"):format(nOP,nRG,nAA,nRG,nBB))
  w(("elseif %s==21 then local %s={};for %s=%s,%s do %s[#%s+1]=tostring(%s[%s]);end;%s[%s]=table.concat(%s);"):format(
    nOP,nTMP,nLI,nBB,nCC,nTMP,nTMP,nRG,nLI,nRG,nAA,nTMP))
  w(("elseif %s==22 then %s=%s+%s;"):format(nOP,nPC,nPC,nSBX))
  w(("elseif %s==23 then if(%s(%s,%s,%s)==%s(%s,%s,%s))~=(%s~=0)then %s=%s+1;end;"):format(
    nOP,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC,nAA,nPC,nPC))
  w(("elseif %s==24 then if(%s(%s,%s,%s)<%s(%s,%s,%s))~=(%s~=0)then %s=%s+1;end;"):format(
    nOP,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC,nAA,nPC,nPC))
  w(("elseif %s==25 then if(%s(%s,%s,%s)<=%s(%s,%s,%s))~=(%s~=0)then %s=%s+1;end;"):format(
    nOP,nRK,nRG,nKK,nBB,nRK,nRG,nKK,nCC,nAA,nPC,nPC))
  w(("elseif %s==26 then if(not not %s[%s])~=(%s~=0)then %s=%s+1;end;"):format(nOP,nRG,nAA,nCC,nPC,nPC))
  w(("elseif %s==27 then if(not not %s[%s])~=(%s~=0)then %s=%s+1;else %s[%s]=%s[%s];end;"):format(
    nOP,nRG,nBB,nCC,nPC,nPC,nRG,nAA,nRG,nBB))
  w(("elseif %s==28 then;"):format(nOP))
  w(("local %s=%s[%s];local %s={};"):format(nFN,nRG,nAA,nARG))
  w(("if %s==1 then;"):format(nBB))
  w(("elseif %s==0 then for %s=%s+1,%s.%s do if %s[%s]~=nil then %s[#%s+1]=%s[%s];end;end;"):format(
    nBB,nLI,nAA,nPR,pMS,nRG,nLI,nARG,nARG,nRG,nLI))
  w(("else for %s=%s+1,%s+%s-1 do %s[#%s+1]=%s[%s];end;end;"):format(nLI,nAA,nAA,nBB,nARG,nARG,nRG,nLI))
  w(("local %s=%s(%s(%s(%s)));"):format(nRES,nPKK,nFN,nUNP,nARG))
  w(("if %s==0 then for %s=0,%s.n-1 do %s[%s+%s]=%s[%s+1];end;"):format(nCC,nLI,nRES,nRG,nAA,nLI,nRES,nLI))
  w(("elseif %s==1 then;else for %s=0,%s-2 do %s[%s+%s]=%s[%s+1];end;end;"):format(nCC,nLI,nCC,nRG,nAA,nLI,nRES,nLI))
  w(("elseif %s==29 then;"):format(nOP))
  w(("local %s=%s[%s];local %s={};"):format(nFN,nRG,nAA,nARG))
  w(("for %s=%s+1,%s+%s-1 do %s[#%s+1]=%s[%s];end;"):format(nLI,nAA,nAA,nBB,nARG,nARG,nRG,nLI))
  w(("return %s(%s(%s));"):format(nFN,nUNP,nARG))
  w(("elseif %s==30 then;"):format(nOP))
  w(("if %s==0 then;"):format(nBB))
  w(("local %s={};for %s=%s,%s.%s do if %s[%s]~=nil then %s[#%s+1]=%s[%s];end;end;"):format(
    nRET,nLI,nAA,nPR,pMS,nRG,nLI,nRET,nRET,nRG,nLI))
  w(("return %s(%s);"):format(nUNP,nRET))
  w(("elseif %s==1 then return;"):format(nBB))
  w(("else local %s={};for %s=%s,%s+%s-2 do %s[#%s+1]=%s[%s];end;return %s(%s);end;"):format(
    nRET,nLI,nAA,nAA,nBB,nRET,nRET,nRG,nLI,nUNP,nRET))
  w(("elseif %s==31 then;"):format(nOP))
  w(("%s[%s]=%s[%s]+%s[%s+2];"):format(nRG,nAA,nRG,nAA,nRG,nAA))
  w(("if(%s[%s+2]>0 and %s[%s]<=%s[%s+1])or(%s[%s+2]<0 and %s[%s]>=%s[%s+1])then;"):format(
    nRG,nAA,nRG,nAA,nRG,nAA,nRG,nAA,nRG,nAA,nRG,nAA))
  w(("%s=%s+%s;%s[%s+3]=%s[%s];end;"):format(nPC,nPC,nSBX,nRG,nAA,nRG,nAA))
  w(("elseif %s==32 then %s[%s]=%s[%s]-%s[%s+2];%s=%s+%s;"):format(
    nOP,nRG,nAA,nRG,nAA,nRG,nAA,nPC,nPC,nSBX))
  w(("elseif %s==33 then;"):format(nOP))
  w(("local %s=%s[%s];"):format(nFN,nRG,nAA))
  w(("local %s=%s(%s(%s[%s+1],%s[%s+2]));"):format(nRES,nPKK,nFN,nRG,nAA,nRG,nAA))
  w(("if %s[1]~=nil then for %s=1,%s do %s[%s+2+%s]=%s[%s];end;%s[%s+2]=%s[1];"):format(
    nRES,nLI,nCC,nRG,nAA,nLI,nRES,nLI,nRG,nAA,nRES))
  w(("else %s=%s+1;end;"):format(nPC,nPC))
  w(("elseif %s==34 then;"):format(nOP))
  w(("local %s=(%s-1)*50;for %s=1,%s do %s[%s][%s+%s]=%s[%s+%s];end;"):format(
    nBASE,nCC,nLI,nBB,nRG,nAA,nBASE,nLI,nRG,nAA,nLI))
  w(("elseif %s==36 then;"):format(nOP))
  w(("local %s=%s[%s+1];local %s={};"):format(nCH,nPP,nBX,nCU))
  w(("for %s=1,%s.%s do;"):format(nLI,nCH,pNU))
  w(("local %s=%s[%s];%s=%s+1;"):format(nPS,nCD,nPC,nPC,nPC))
  w(("if %s.%s==0 then %s[%s]=%s[%s.%s];else %s[%s]=%s[%s.%s+1];end;"):format(
    nPS,fOP,nCU,nLI,nRG,nPS,fB,nCU,nLI,nUV,nPS,fB))
  w("end;")
  w(("%s[%s]=function(...) return %s(%s,%s,...);end;"):format(nRG,nAA,nX,nCH,nCU))
  w(("elseif %s==37 then;"):format(nOP))
  w(("if %s==0 then for %s=%s,%s.%s do %s[%s]=%s[%s-%s+1];end;"):format(
    nBB,nLI,nAA,nPR,pMS,nRG,nLI,nVA,nLI,nVS))
  w(("else for %s=0,%s-1 do %s[%s+%s]=%s[%s+1];end;end;"):format(nLI,nBB,nRG,nAA,nLI,nVA,nLI))
  w("end;")   -- end if/elseif
  w("end;")   -- end while
  w("end;")   -- end executor

  w(("%s(%s(),{});"):format(nX,nDP))

  return (table.concat(L,"\n"):gsub("\n"," "))
end

return VMGen
