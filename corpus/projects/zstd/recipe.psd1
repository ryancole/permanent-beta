# Build recipe for zstd (https://github.com/facebook/zstd, BSD license; also GPLv2). Read by
# corpus/build-projects.ps1.
#
# Builds the `zstd` command-line tool with the library compiled in, like zstd's CMake build: multithreaded,
# no legacy-format support (lib/legacy left out), xxHash namespaced. A large codebase with real churn between
# releases. Source lists use wildcards because files come and go (programs/lorem.c in 1.5.6,
# lib/compress/zstd_preSplit.c in 1.5.7). Sources are cloned at build time into target/corpus-src/ and are
# never committed here.
@{
    Name     = 'zstd'
    Repo     = 'https://github.com/facebook/zstd.git'
    License  = 'BSD-3-Clause OR GPL-2.0-only'
    # Consecutive pairs are scored: v1.5.5 -> v1.5.6 and v1.5.6 -> v1.5.7.
    Versions = @('v1.5.5', 'v1.5.6', 'v1.5.7')
    Exe      = 'zstd'
    Sources  = @(
        'lib/common/*.c', 'lib/compress/*.c', 'lib/decompress/*.c', 'lib/dictBuilder/*.c', 'programs/*.c'
    )
    # Functions renamed between releases, keyed by the newer tag (old name = new name), each checked by hand
    # against the sources. Only renames the engine actually matched are listed so far; an undeclared rename
    # shows up as a "wrong" match and gets checked and added here.
    Renames  = @{
        'v1.5.6' = @{
            'usage_advanced'        = 'usageAdvanced'
            'badusage'              = 'badUsage'
            # The body became BIT_reloadDStream_internal and BIT_reloadDStream's call was retargeted to it; a
            # new thin BIT_reloadDStreamFast wrapper exists only in objects that call it. Joined per object:
            # where the new wrapper exists, the old function is joined to it by name instead.
            'BIT_reloadDStreamFast' = 'BIT_reloadDStream_internal'
        }
        'v1.5.7' = @{
            'ZSTD_cwksp_reserve_aligned'                     = 'ZSTD_cwksp_reserve_aligned64'
            'ZSTD_copySequencesToSeqStoreNoBlockDelim'       = 'ZSTD_transferSequences_noDelim'
            'ZSTD_copySequencesToSeqStoreExplicitBlockDelim' = 'ZSTD_transferSequences_wBlockDelim'
            # Same call site and role; the unused cctx parameter was dropped.
            'ZSTDMT_serialState_update'                      = 'ZSTDMT_serialState_genSequences'
            'init_nbThreads'                                 = 'default_nbThreads'
            # Same body and strings; it now returns int instead of BMK_benchOutcome_t. Found by the AI proposer.
            'BMK_benchCLevel'                                = 'BMK_benchCLevels'
        }
    }
    Include  = @('lib', 'lib/common')
    Defines  = @('_CRT_SECURE_NO_WARNINGS', 'XXH_NAMESPACE=ZSTD_', 'ZSTD_LEGACY_SUPPORT=0', 'ZSTD_MULTITHREAD')
    Cl       = @('/W3')
}
