# Build recipe for yaml-cpp (https://github.com/jbeder/yaml-cpp, MIT license). Read by
# corpus/build-projects.ps1.
#
# The corpus's second C++ project, heavier than TinyXML-2 on exceptions (the YAML::Exception hierarchy, thrown
# across the parser and node API), the STL (std::string, std::vector, std::map, shared_ptr) and templates
# (YAML::convert<T>, node iterators). Builds `util/read.cpp`, which parses YAML through a virtual
# YAML::EventHandler, with the library compiled in statically. src/parse.cpp is left out: its base name would
# clash with util/parse.cpp's in the object directory, and read.cpp doesn't use it. Releases are years apart
# (2021, 2023, 2026), so there is real churn: 0.9.0 adds dragonbox float formatting (src/fptostring.cpp).
# Sources are cloned at build time into target/corpus-src/ and are never committed here.
@{
    Name     = 'yaml-cpp'
    Repo     = 'https://github.com/jbeder/yaml-cpp.git'
    License  = 'MIT'
    # Consecutive pairs are scored: 0.7.0 -> 0.8.0 and 0.8.0 -> 0.9.0 (0.8.0 dropped the tag prefix).
    Versions = @('yaml-cpp-0.7.0', '0.8.0', 'yaml-cpp-0.9.0')
    Exe      = 'read'
    Sources  = @('src/[a-o]*.cpp', 'src/[q-z]*.cpp', 'src/parser.cpp', 'src/contrib/*.cpp', 'util/read.cpp')
    Include  = @('include', 'src')
    Defines  = @('_CRT_SECURE_NO_WARNINGS', 'YAML_CPP_STATIC_DEFINE')
    Cl       = @('/W3', '/EHsc', '/std:c++17')
    # Renames, keyed by the newer tag (old name = new name), each checked by hand against the sources.
    # 0.9.0's emitterutils.cpp calls std::none_of(str, str + size, ...) instead of std::none_of(str.begin(),
    # str.end(), ...), so the STL helper it instantiates unwraps a const char* instead of a string iterator.
    Renames  = @{
        'yaml-cpp-0.9.0' = @{
            '??$_Get_unwrapped@AEBV?$_String_const_iterator@V?$_String_val@U?$_Simple_types@D@std@@@std@@@std@@@std@@YA?A_TAEBV?$_String_const_iterator@V?$_String_val@U?$_Simple_types@D@std@@@std@@@0@@Z' = '??$_Get_unwrapped@AEBQEBD@std@@YA?A_TAEBQEBD@Z'
        }
    }
    # PGO training (flag set o2-pgo): parse the repository's .clang-format (YAML, present in every scored tag).
    Train    = @(@{ Args = @('{src}\.clang-format') })
}
