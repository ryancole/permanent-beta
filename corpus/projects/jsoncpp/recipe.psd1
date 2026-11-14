# Build recipe for JsonCpp (https://github.com/open-source-parsers/jsoncpp, MIT license or public domain). Read
# by corpus/build-projects.ps1.
#
# The corpus's third C++ project, for calibrating the C++ guesses (table-slot anchors, the code-tables check, the
# wrapper rule) beyond TinyXML-2 and yaml-cpp. Builds `jsontestrunner`, the project's test driver, with the
# library compiled in. JsonCpp is class-based (Json::Value, the CharReader/StreamWriter factories and their
# virtual interfaces, the deprecated Reader/Writer hierarchy), uses exceptions (Json::Exception, RuntimeError,
# LogicError) and the STL (std::string, std::map, std::vector, std::unique_ptr). The releases are 2024-2026, a few
# hundred changed lines apart. Sources are cloned at build time into target/corpus-src/ and are never committed
# here.
@{
    Name     = 'jsoncpp'
    Repo     = 'https://github.com/open-source-parsers/jsoncpp.git'
    License  = 'MIT'
    # Consecutive pairs are scored: 1.9.6 -> 1.9.7 and 1.9.7 -> 1.9.8.
    Versions = @('1.9.6', '1.9.7', '1.9.8')
    Exe      = 'jsontestrunner'
    Sources  = @(
        'src/lib_json/json_reader.cpp', 'src/lib_json/json_value.cpp', 'src/lib_json/json_writer.cpp',
        'src/jsontestrunner/main.cpp'
    )
    Include  = @('include', 'src/lib_json')
    Defines  = @('_CRT_SECURE_NO_WARNINGS')
    Cl       = @('/W3', '/EHsc')
    # Renames, keyed by the newer tag (old name = new name), each checked by hand against the sources. 1.9.7 passes
    # `0u` instead of `0` as InRange's lower bound in asUInt, asUInt64, isConvertibleTo and friends, so the same
    # template's instantiations for those callers change from T = int to T = unsigned int.
    Renames  = @{
        '1.9.7' = @{
            '??$InRange@HI@Json@@YA_NNHI@Z'   = '??$InRange@II@Json@@YA_NNII@Z'
            '??$InRange@H_K@Json@@YA_NNH_K@Z' = '??$InRange@I_K@Json@@YA_NNI_K@Z'
        }
    }
    # PGO training (flag set o2-pgo): the runner parses, rewrites and re-parses four of the project's test files,
    # run from test/data with relative names (it writes `.actual` and `.rewrite` files next to its input and puts
    # the path into strings, so an absolute path would make the profile depend on the checkout's location).
    Train    = @(
        @{ Args = @('legacy_test_complex_01.json'); Cwd = '{src}/test/data' }
        @{ Args = @('legacy_test_large_01.json'); Cwd = '{src}/test/data' }
        @{ Args = @('legacy_test_comment_01.json'); Cwd = '{src}/test/data' }
        @{ Args = @('legacy_test_real_01.json'); Cwd = '{src}/test/data' }
    )
}
