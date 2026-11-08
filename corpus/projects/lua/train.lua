-- PGO training workload for the Lua corpus (corpus/build-projects.ps1, flag set o2-pgo). Exercises the parser,
-- VM, GC, strings, tables, closures, coroutines, errors and the standard libraries. Runs on every scored tag, so
-- it uses only Lua 5.4 features present in 5.4.6.

local t = {}
for i = 1, 20000 do t[i] = (i * 7919) % 10007 end
table.sort(t)
table.sort(t, function(a, b) return a > b end)

local words = {}
for w in string.gmatch(string.rep("the quick brown fox jumps over the lazy dog ", 500), "%a+") do
  words[#words + 1] = w:upper():reverse()
end
local s = table.concat(words, ",")
s = s:gsub("(%a)(%a*)", function(a, b) return a:lower() .. b end)
assert(#string.format("%d %5.2f %q %x", 42, math.pi, "a\nb", 255) > 0)

local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
assert(fib(22) == 17711)

local co = coroutine.wrap(function()
  for i = 1, 1000 do coroutine.yield(i) end
end)
local sum = 0
for _ = 1, 1000 do sum = sum + co() end

local ok, err = pcall(function() error({ code = 1 }) end)
assert(not ok and err.code == 1)
ok = pcall(function() return nil + 1 end)
assert(not ok)

local mt = setmetatable({}, { __index = function(_, k) return k * 2 end, __call = function(_, x) return x end })
assert(mt[21] == 42 and mt(7) == 7)

local parts = {}
for i = 1, 2000 do parts[#parts + 1] = ("%d"):format(i) end
local code = "return " .. table.concat(parts, "+")
assert(load(code)() == 2001000)

local big = {}
for i = 1, 50000 do big[i] = { i, tostring(i) } end
big = nil
collectgarbage()
collectgarbage("step")

print(utf8.char(72, 228, 8364), utf8.len("häl€"), os.time() > 0, math.floor(3.7), string.pack("i4", 7):len())
