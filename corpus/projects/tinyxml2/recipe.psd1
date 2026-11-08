# Build recipe for TinyXML-2 (https://github.com/leethomason/tinyxml2, zlib license). Read by
# corpus/build-projects.ps1.
#
# The corpus's first C++ project: builds `xmltest`, the project's own test driver, with the library compiled in.
# TinyXML-2 is class-based with many virtual functions (XMLNode's ToElement/ToText/..., Accept, ShallowClone,
# the XMLVisitor callbacks), so a lot of code is reachable only through vtables, and many virtual overrides are
# tiny and byte-identical. Map-file names are decorated (C++ mangling), so overloads stay apart in the answer key.
# 10.1.0 -> 11.0.0 only bumps the version number, so the scored pairs stop at 10.1.0. Sources are cloned at build
# time into target/corpus-src/ and are never committed here.
@{
    Name     = 'tinyxml2'
    Repo     = 'https://github.com/leethomason/tinyxml2.git'
    License  = 'Zlib'
    # Consecutive pairs are scored: 9.0.0 -> 10.0.0 and 10.0.0 -> 10.1.0.
    Versions = @('9.0.0', '10.0.0', '10.1.0')
    Exe      = 'xmltest'
    Sources  = @('tinyxml2.cpp', 'xmltest.cpp')
    Defines  = @('_CRT_SECURE_NO_WARNINGS')
    Cl       = @('/W3', '/EHsc')
    # PGO training (flag set o2-pgo): xmltest's own test suite, run from the source tree (it reads resources/).
    Train    = @(@{ Args = @(); Cwd = '{src}' })
}
