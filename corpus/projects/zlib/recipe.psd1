# Build recipe for zlib (https://zlib.net, zlib license). Read by corpus/build-projects.ps1.
#
# Builds the `minigzip` test program with the zlib sources compiled in (as zlib's own win32/Makefile.msc does),
# so the executable has no exports and the analyzer sees zlib's functions only as code. Sources are cloned at
# build time into target/corpus-src/ and are never committed here.
@{
    Name     = 'zlib'
    Repo     = 'https://github.com/madler/zlib.git'
    License  = 'zlib'
    # Consecutive pairs are scored: v1.2.13 -> v1.3 (K&R-to-ANSI rewrite of every definition) and
    # v1.3 -> v1.3.1 (a small bug-fix release).
    Versions = @('v1.2.13', 'v1.3', 'v1.3.1')
    Exe      = 'minigzip'
    Sources  = @(
        'adler32.c', 'compress.c', 'crc32.c', 'deflate.c', 'gzclose.c', 'gzlib.c', 'gzread.c', 'gzwrite.c',
        'infback.c', 'inffast.c', 'inflate.c', 'inftrees.c', 'trees.c', 'uncompr.c', 'zutil.c',
        'test/minigzip.c'
    )
    Defines  = @('_CRT_SECURE_NO_DEPRECATE', '_CRT_NONSTDC_NO_DEPRECATE')
    Cl       = @('/W3')
}
