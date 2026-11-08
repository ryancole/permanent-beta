# Build recipe for Lua (https://www.lua.org, MIT license). Read by corpus/build-projects.ps1.
#
# Builds the standalone `lua` interpreter with the core and standard libraries compiled in, from the official
# GitHub mirror of Lua's development repository. Left out: onelua.c (all sources #included into one file) and
# ltests.c (internal test library, empty unless LUA_DEBUG is defined). Sources are cloned at build time into
# target/corpus-src/ and are never committed here.
@{
    Name     = 'lua'
    Repo     = 'https://github.com/lua/lua.git'
    License  = 'MIT'
    # Consecutive pairs are scored: v5.4.6 -> v5.4.7 and v5.4.7 -> v5.4.8 (bug-fix releases with real code
    # changes in the parser, GC and libraries).
    Versions = @('v5.4.6', 'v5.4.7', 'v5.4.8')
    Exe      = 'lua'
    Sources  = @(
        'lapi.c', 'lauxlib.c', 'lbaselib.c', 'lcode.c', 'lcorolib.c', 'lctype.c', 'ldblib.c', 'ldebug.c',
        'ldo.c', 'ldump.c', 'lfunc.c', 'lgc.c', 'linit.c', 'liolib.c', 'llex.c', 'lmathlib.c', 'lmem.c',
        'loadlib.c', 'lobject.c', 'lopcodes.c', 'loslib.c', 'lparser.c', 'lstate.c', 'lstring.c', 'lstrlib.c',
        'ltable.c', 'ltablib.c', 'ltm.c', 'lua.c', 'lundump.c', 'lutf8lib.c', 'lvm.c', 'lzio.c'
    )
    # Functions renamed between releases, keyed by the newer tag (old name = new name). Each was checked by
    # hand against the sources; the answer key joins functions by name and would score these as wrong.
    Renames  = @{
        # 5.4.7 made five internal functions static and dropped their prefix (same bodies and signatures), and
        # renamed ldebug.c's gxf to isEnv (same signature; it now calls basicgetobjname).
        'v5.4.7' = @{
            'luaD_tryfuncTM' = 'tryfuncTM'
            'luaE_freeCI'    = 'freeCI'
            'luaK_codeAsBx'  = 'codeAsBx'
            'luaK_exp2RK'    = 'exp2RK'
            'luaK_isKint'    = 'isKint'
            'gxf'            = 'isEnv'
        }
    }
    Defines  = @('_CRT_SECURE_NO_WARNINGS')
    Cl       = @('/W3')
    # PGO builds get a fixed string-hash seed (pgo_seed.h), so training, and the build, are reproducible.
    PgoCl    = @('/FI{recipe}/pgo_seed.h')
    # PGO training (flag set o2-pgo): corpus/projects/lua/train.lua, run from the recipe directory so the chunk
    # name is `train.lua` wherever the checkout is, with package.path and cpath fixed: by default Lua puts the
    # executable's directory into them (`!`, loadlib.c's setprogdir). build-projects.ps1 also keeps the path out of
    # argv[0] (arg[-1]); its length alone still changed the profile. With the absolute paths, CI's checkout
    # (D:\a\permanent-beta\...) gave a different profile than a longer local one: Lua 5.4.8's collectargs went to
    # review there, 838 correct instead of 839.
    Train    = @(@{
            Args = @('train.lua'); Cwd = '{recipe}'
            Env  = @{ LUA_PATH_5_4 = '.\?.lua'; LUA_CPATH_5_4 = '.\?.dll' }
        })
}
