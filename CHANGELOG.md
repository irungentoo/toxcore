

## v0.2.16

### Merged PRs:

- [#2069](https://github.com/TokTok/c-toxcore/pull/2069) chore: Simplify and speed up nacl build using toxchat/nacl.
- [#2066](https://github.com/TokTok/c-toxcore/pull/2066) test: Add a profiling script and Dockerfile.
- [#2058](https://github.com/TokTok/c-toxcore/pull/2058) fix: properly deallocate frozen peers
- [#2056](https://github.com/TokTok/c-toxcore/pull/2056) cleanup: Avoid implicit boolean and floating point conversions in decls.
- [#2055](https://github.com/TokTok/c-toxcore/pull/2055) cleanup: Avoid implicit bool conversions in logical operators.
- [#2053](https://github.com/TokTok/c-toxcore/pull/2053) cleanup: Enable tokstyle's `-Wlarge-struct-params`.
- [#2052](https://github.com/TokTok/c-toxcore/pull/2052) fix: Fix return type of functions returning uint64_t.
- [#2049](https://github.com/TokTok/c-toxcore/pull/2049) cleanup: Apply stronger type checks and fix errors.
- [#2047](https://github.com/TokTok/c-toxcore/pull/2047) feat: Improve how we share TCP relays with friends
- [#2046](https://github.com/TokTok/c-toxcore/pull/2046) cleanup: Avoid implicit pointer-to-bool conversion in `if` in toxav.
- [#2043](https://github.com/TokTok/c-toxcore/pull/2043) refactor: Compare pointers in if conditions to nullptr.
- [#2041](https://github.com/TokTok/c-toxcore/pull/2041) fix: file transfer bug introduced in commit 2073d02
- [#2039](https://github.com/TokTok/c-toxcore/pull/2039) refactor: Add a bit more logging; change WARNING to ERROR.
- [#2036](https://github.com/TokTok/c-toxcore/pull/2036) chore: Add BUILD file for websockify.
- [#2035](https://github.com/TokTok/c-toxcore/pull/2035) chore: fine tune fuzzing settings
- [#2033](https://github.com/TokTok/c-toxcore/pull/2033) cleanup: Add some more error path logging to TCP server code.
- [#2032](https://github.com/TokTok/c-toxcore/pull/2032) chore: update the list of CMake options & Windows Docker build deps
- [#2031](https://github.com/TokTok/c-toxcore/pull/2031) fix: remove bogus asserts in fuzzer harness
- [#2030](https://github.com/TokTok/c-toxcore/pull/2030) chore: expand fuzzing to toxsave
- [#2028](https://github.com/TokTok/c-toxcore/pull/2028) fix: syntax error introduced in 8bf37994fd12acec9e3010437502f478399b99b4
- [#2027](https://github.com/TokTok/c-toxcore/pull/2027) fix: add continous fuzzing
- [#2026](https://github.com/TokTok/c-toxcore/pull/2026) chore: Fix implicit declaration warning in fuzz build
- [#2025](https://github.com/TokTok/c-toxcore/pull/2025) chore: add continous fuzzing to our CI
- [#2024](https://github.com/TokTok/c-toxcore/pull/2024) perf: Reduce minimal encoding size of packed events.
- [#2023](https://github.com/TokTok/c-toxcore/pull/2023) cleanup: Add wrapper library for msgpack pack functions
- [#2022](https://github.com/TokTok/c-toxcore/pull/2022) cleanup: Split tox_unpack into two smaller libs
- [#2021](https://github.com/TokTok/c-toxcore/pull/2021) chore: Disable non-null attributes by default.
- [#2019](https://github.com/TokTok/c-toxcore/pull/2019) chore: Silence clang compile warnings causing circle-ci/asan to fail
- [#2018](https://github.com/TokTok/c-toxcore/pull/2018) fix: Coverty scan
- [#2016](https://github.com/TokTok/c-toxcore/pull/2016) docs: Add libmsgpack dependency in INSTALL.md
- [#2015](https://github.com/TokTok/c-toxcore/pull/2015) fix: shared toxcore autotools build failing
- [#2013](https://github.com/TokTok/c-toxcore/pull/2013) cleanup: Don't use VLAs for huge allocations.
- [#2011](https://github.com/TokTok/c-toxcore/pull/2011) fix: Conan build link failures
- [#2010](https://github.com/TokTok/c-toxcore/pull/2010) chore: Remove duplicate source file in autotools build.
- [#2008](https://github.com/TokTok/c-toxcore/pull/2008) chore: get skeletons out of the closet
- [#2007](https://github.com/TokTok/c-toxcore/pull/2007) feat: add bash-completion for tox-bootstrapd
- [#2006](https://github.com/TokTok/c-toxcore/pull/2006) cleanup: Add more nonnull and nullable annotations.
- [#2002](https://github.com/TokTok/c-toxcore/pull/2002) cleanup: Add nonnull annotations to function definitions.
- [#2001](https://github.com/TokTok/c-toxcore/pull/2001) chore: Add an undefined behaviour/integer sanitizer build.
- [#1999](https://github.com/TokTok/c-toxcore/pull/1999) chore: Speed up cmake builds with `UNITY_BUILD`.
- [#1996](https://github.com/TokTok/c-toxcore/pull/1996) feat: Add unpacker functions for events structures.
- [#1993](https://github.com/TokTok/c-toxcore/pull/1993) feat: Add binary packing functions for tox events.
- [#1992](https://github.com/TokTok/c-toxcore/pull/1992) chore: Set up an Android CI job
- [#1988](https://github.com/TokTok/c-toxcore/pull/1988) cleanup: Make LAN discovery thread-safe without data races.
- [#1987](https://github.com/TokTok/c-toxcore/pull/1987) cleanup: Comply with new cimple callback rules.
- [#1985](https://github.com/TokTok/c-toxcore/pull/1985) cleanup: Split msi callback array into 1 member per callback
- [#1982](https://github.com/TokTok/c-toxcore/pull/1982) chore: Add an easy way to run autotools and circleci builds locally.
- [#1979](https://github.com/TokTok/c-toxcore/pull/1979) chore: Update readme header
- [#1952](https://github.com/TokTok/c-toxcore/pull/1952) feat: Add async event handling (callbacks) code.
- [#1935](https://github.com/TokTok/c-toxcore/pull/1935) feat: add DHT queries to private API
- [#1668](https://github.com/TokTok/c-toxcore/pull/1668) perf: Take advantage of fast networks for file transfers

### Closed issues:

- [#2009](https://github.com/TokTok/c-toxcore/issues/2009) Autotools build fails
- [#2004](https://github.com/TokTok/c-toxcore/issues/2004) Add `nullable` and `nonnull` annotations to all functions.
- [#1998](https://github.com/TokTok/c-toxcore/issues/1998) Large stack allocations
- [#1977](https://github.com/TokTok/c-toxcore/issues/1977) Turn array of callbacks in msi.h into separate callbacks.
- [#1670](https://github.com/TokTok/c-toxcore/issues/1670) Broken link in readme
- [#405](https://github.com/TokTok/c-toxcore/issues/405) Remove all¹ uses of global state in toxcore
- [#340](https://github.com/TokTok/c-toxcore/issues/340) Set up a continuous integration build for Android
- [#236](https://github.com/TokTok/c-toxcore/issues/236) Tox file transfers do not use available bandwidth
- [#128](https://github.com/TokTok/c-toxcore/issues/128) Toxcore should provide an easy, local method for making sure Travis checks will pass

## v0.2.15

### Merged PRs:

- [#1984](https://github.com/TokTok/c-toxcore/pull/1984) fix: Reduce logging verbosity even more.
- [#1983](https://github.com/TokTok/c-toxcore/pull/1983) chore: Release 0.2.15
- [#1980](https://github.com/TokTok/c-toxcore/pull/1980) fix: Reduce logging verbosity in TCP server.

## v0.2.14

### Merged PRs:

- [#1978](https://github.com/TokTok/c-toxcore/pull/1978) chore: Release 0.2.14
- [#1976](https://github.com/TokTok/c-toxcore/pull/1976) docs: Make crypto_core.h appear on doxygen.
- [#1975](https://github.com/TokTok/c-toxcore/pull/1975) refactor: use proper method for generating random numbers in a range
- [#1974](https://github.com/TokTok/c-toxcore/pull/1974) docs: Add doxygen configuration and netlify publishing.
- [#1972](https://github.com/TokTok/c-toxcore/pull/1972) chore: Make the last few remaining top level comments doxygen style.
- [#1971](https://github.com/TokTok/c-toxcore/pull/1971) chore: Sync all comments between header and source files.
- [#1968](https://github.com/TokTok/c-toxcore/pull/1968) cleanup: Ensure we limit the system headers included in .h files.
- [#1964](https://github.com/TokTok/c-toxcore/pull/1964) cleanup: Don't pass the whole DHT object to lan discovery.
- [#1958](https://github.com/TokTok/c-toxcore/pull/1958) chore: Make run-infer script use docker.
- [#1956](https://github.com/TokTok/c-toxcore/pull/1956) chore: Disable some cimple warnings for now.
- [#1955](https://github.com/TokTok/c-toxcore/pull/1955) cleanup: Properly copy Node_format using serialized format
- [#1954](https://github.com/TokTok/c-toxcore/pull/1954) cleanup: make functions take const pointer to IP_Port wherever possible
- [#1950](https://github.com/TokTok/c-toxcore/pull/1950) feat: Add WASM build for toxcore and websocket bootstrap node.
- [#1948](https://github.com/TokTok/c-toxcore/pull/1948) fix: potential freeing of an immutable static buffer
- [#1945](https://github.com/TokTok/c-toxcore/pull/1945) fix: Fix bootstrap on emscripten/wasm.
- [#1943](https://github.com/TokTok/c-toxcore/pull/1943) chore: use latest toktok-stack msan version
- [#1942](https://github.com/TokTok/c-toxcore/pull/1942) cleanup: Add some toxav bounds/sanity checks
- [#1940](https://github.com/TokTok/c-toxcore/pull/1940) chore: Use latest instead of versioned toktok-stack image.
- [#1939](https://github.com/TokTok/c-toxcore/pull/1939) chore: Rename bazel-release to -opt and -debug to -dbg.
- [#1938](https://github.com/TokTok/c-toxcore/pull/1938) cleanup: small refactor of DHT getnodes function
- [#1937](https://github.com/TokTok/c-toxcore/pull/1937) cleanup: remove brackets from ip_ntoa ipv6 formatting
- [#1933](https://github.com/TokTok/c-toxcore/pull/1933) chore: Add a Bazel Buildifier CI job
- [#1932](https://github.com/TokTok/c-toxcore/pull/1932) test: separate run_auto_tests into a library (revival of #1505)
- [#1929](https://github.com/TokTok/c-toxcore/pull/1929) cleanup: make some non-const pointers const
- [#1928](https://github.com/TokTok/c-toxcore/pull/1928) fix: unintentional integer down-casts
- [#1926](https://github.com/TokTok/c-toxcore/pull/1926) fix: group av memory leak
- [#1924](https://github.com/TokTok/c-toxcore/pull/1924) test: refactor autotest live network bootstrapping
- [#1923](https://github.com/TokTok/c-toxcore/pull/1923) fix: corruption in key files, making it unable to load when node starts.
- [#1922](https://github.com/TokTok/c-toxcore/pull/1922) chore: Don't run sonar scan on pull requests.
- [#1920](https://github.com/TokTok/c-toxcore/pull/1920) cleanup: refactor group audio packet data handling
- [#1918](https://github.com/TokTok/c-toxcore/pull/1918) chore: Run sonar scan on pull requests.
- [#1917](https://github.com/TokTok/c-toxcore/pull/1917) fix: buffer overwrite in bootstrap config
- [#1916](https://github.com/TokTok/c-toxcore/pull/1916) chore: Add a make_single_file script, used for CI.
- [#1915](https://github.com/TokTok/c-toxcore/pull/1915) cleanup: replace magic numbers with appropriately named constants
- [#1914](https://github.com/TokTok/c-toxcore/pull/1914) chore: Add cpplint to the CI.
- [#1912](https://github.com/TokTok/c-toxcore/pull/1912) cleanup: Remove uses of `strcpy` and `sprintf`.
- [#1910](https://github.com/TokTok/c-toxcore/pull/1910) cleanup: Remove our only use of flexible array members in toxcore.
- [#1909](https://github.com/TokTok/c-toxcore/pull/1909) chore: Expose public API headers as files in bazel.
- [#1906](https://github.com/TokTok/c-toxcore/pull/1906) cleanup: Split large switch statement into functions.
- [#1905](https://github.com/TokTok/c-toxcore/pull/1905) chore: Mark unsafe code as testonly.
- [#1903](https://github.com/TokTok/c-toxcore/pull/1903) cleanup: Even more pointer-to-const parameters.
- [#1901](https://github.com/TokTok/c-toxcore/pull/1901) cleanup: Make parameters pointers-to-const where possible.
- [#1900](https://github.com/TokTok/c-toxcore/pull/1900) cleanup: Remove old check Suite compat layer.
- [#1899](https://github.com/TokTok/c-toxcore/pull/1899) cleanup: Make `Networking_Core` pointer-to-const where possible.
- [#1898](https://github.com/TokTok/c-toxcore/pull/1898) cleanup: Use pointer cast instead of memcpy in qsort callback.
- [#1897](https://github.com/TokTok/c-toxcore/pull/1897) refactor: Deduplicate a bunch of code in TCP client/server.
- [#1894](https://github.com/TokTok/c-toxcore/pull/1894) cleanup: Deduplicate a somewhat complex loop in DHT.c.
- [#1891](https://github.com/TokTok/c-toxcore/pull/1891) cleanup: Remove our only use of sprintf.
- [#1889](https://github.com/TokTok/c-toxcore/pull/1889) cleanup: Stop using `strerror` directly.
- [#1887](https://github.com/TokTok/c-toxcore/pull/1887) test: Add two more bootstrap/TCP nodes to autotests
- [#1884](https://github.com/TokTok/c-toxcore/pull/1884) chore: Add mypy Python type check.
- [#1883](https://github.com/TokTok/c-toxcore/pull/1883) chore: Add sonar-scan analysis on pushes.
- [#1881](https://github.com/TokTok/c-toxcore/pull/1881) cleanup: Merge crypto_core and crypto_core_mem.
- [#1880](https://github.com/TokTok/c-toxcore/pull/1880) chore: Run static analysers in multiple variants.
- [#1879](https://github.com/TokTok/c-toxcore/pull/1879) fix: Fix `toxav_basic_test` buffer overflow.
- [#1878](https://github.com/TokTok/c-toxcore/pull/1878) fix: don't count filetransfer as sending until accepted
- [#1877](https://github.com/TokTok/c-toxcore/pull/1877) fix: Fix some uninitialised memory errors found by valgrind.
- [#1876](https://github.com/TokTok/c-toxcore/pull/1876) chore: Ignore some failures in bazel-tsan.
- [#1875](https://github.com/TokTok/c-toxcore/pull/1875) chore: Add asan/tsan bazel builds.
- [#1874](https://github.com/TokTok/c-toxcore/pull/1874) cleanup: replace all instances of atoi with strtol
- [#1873](https://github.com/TokTok/c-toxcore/pull/1873) chore: Enable layering check in all c-toxcore build files.
- [#1871](https://github.com/TokTok/c-toxcore/pull/1871) chore: Enable compiler layering check.
- [#1870](https://github.com/TokTok/c-toxcore/pull/1870) chore: Disable the OpenMP cracker in bazel for now.
- [#1867](https://github.com/TokTok/c-toxcore/pull/1867) chore: Retry asan/tsan tests a few more times.
- [#1866](https://github.com/TokTok/c-toxcore/pull/1866) chore: Run tokstyle with 3 cores.
- [#1865](https://github.com/TokTok/c-toxcore/pull/1865) cleanup: Remove extra parens around function arguments.
- [#1864](https://github.com/TokTok/c-toxcore/pull/1864) cleanup: Don't use memcpy where assignment can be used.
- [#1862](https://github.com/TokTok/c-toxcore/pull/1862) chore: Remove all references to Travis CI.
- [#1861](https://github.com/TokTok/c-toxcore/pull/1861) cleanup: Use `calloc` instead of `malloc` for struct allocations.
- [#1860](https://github.com/TokTok/c-toxcore/pull/1860) cleanup: Fix `calloc` argument order.
- [#1857](https://github.com/TokTok/c-toxcore/pull/1857) chore: Get all* autotests working with MSVC
- [#1853](https://github.com/TokTok/c-toxcore/pull/1853) cleanup: Remove useless parentheses.
- [#1850](https://github.com/TokTok/c-toxcore/pull/1850) chore: Add a GH Actions code coverage job
- [#1845](https://github.com/TokTok/c-toxcore/pull/1845) fix: use correct sample size in toxav_basic_test
- [#1844](https://github.com/TokTok/c-toxcore/pull/1844) cleanup: make struct typedefs have the same name as their struct
- [#1841](https://github.com/TokTok/c-toxcore/pull/1841) cleanup: refactor toxav_call_control
- [#1840](https://github.com/TokTok/c-toxcore/pull/1840) chore: Remove old travis docker scripts.
- [#1837](https://github.com/TokTok/c-toxcore/pull/1837) chore: Add bazel-debug build.
- [#1836](https://github.com/TokTok/c-toxcore/pull/1836) fix: possible unintended negative loop bound
- [#1835](https://github.com/TokTok/c-toxcore/pull/1835) cleanup: remove dead code
- [#1834](https://github.com/TokTok/c-toxcore/pull/1834) cleanup: Reduce the scope of for-loop iterator variables.
- [#1832](https://github.com/TokTok/c-toxcore/pull/1832) fix: a double-unlocking mutex in toxav
- [#1830](https://github.com/TokTok/c-toxcore/pull/1830) chore: Add "tcc" and "compcert" compiler targets.
- [#1820](https://github.com/TokTok/c-toxcore/pull/1820) chore: Add macOS build.
- [#1819](https://github.com/TokTok/c-toxcore/pull/1819) refactor: Extract some functions from the big run_auto_test function.
- [#1818](https://github.com/TokTok/c-toxcore/pull/1818) feat: Add programs for creating savedata & bootstrap keys
- [#1816](https://github.com/TokTok/c-toxcore/pull/1816) cleanup: put breaks inside case braces
- [#1815](https://github.com/TokTok/c-toxcore/pull/1815) test: add ability for autotests to use TCP connections
- [#1813](https://github.com/TokTok/c-toxcore/pull/1813) chore: Login to dockerhub before trying to push to dockerhub.
- [#1812](https://github.com/TokTok/c-toxcore/pull/1812) chore: Only push versioned docker image on tag builds.
- [#1811](https://github.com/TokTok/c-toxcore/pull/1811) chore: Add bootstrap daemon docker image build.
- [#1810](https://github.com/TokTok/c-toxcore/pull/1810) chore: Remove apidsl comment from tox.h.
- [#1807](https://github.com/TokTok/c-toxcore/pull/1807) chore: Don't run CI on master branch pushes.
- [#1802](https://github.com/TokTok/c-toxcore/pull/1802) cleanup: Sync doc comments in a few more .c/.h files.
- [#1801](https://github.com/TokTok/c-toxcore/pull/1801) chore: Fix up a few source code comment and style issues.
- [#1798](https://github.com/TokTok/c-toxcore/pull/1798) chore: merge friend_connections from NGC fork
- [#1797](https://github.com/TokTok/c-toxcore/pull/1797) cleanup: Move `sodium.h` include to front of network.c.
- [#1794](https://github.com/TokTok/c-toxcore/pull/1794) chore: Move cmake-freebsd-stage2 back into the toxcore repo.
- [#1793](https://github.com/TokTok/c-toxcore/pull/1793) chore: Add FreeBSD build to CI.
- [#1792](https://github.com/TokTok/c-toxcore/pull/1792) chore: Add cross compilation CI targets.
- [#1790](https://github.com/TokTok/c-toxcore/pull/1790) cleanup: remove redundant (and incorrect) comments
- [#1789](https://github.com/TokTok/c-toxcore/pull/1789) refactor: rename variable to clarify purpose
- [#1786](https://github.com/TokTok/c-toxcore/pull/1786) cleanup: Remove apidsl; remove `crypto_memcmp`.
- [#1783](https://github.com/TokTok/c-toxcore/pull/1783) cleanup: fix format-source
- [#1779](https://github.com/TokTok/c-toxcore/pull/1779) chore: Update toktok-stack version.
- [#1778](https://github.com/TokTok/c-toxcore/pull/1778) chore: Tie down the use of doxygen comments.
- [#1777](https://github.com/TokTok/c-toxcore/pull/1777) cleanup: Remove crypto_pwhash import.
- [#1776](https://github.com/TokTok/c-toxcore/pull/1776) cleanup: remove unused function argument from set_tcp_connection_status()
- [#1775](https://github.com/TokTok/c-toxcore/pull/1775) cleanup: Remove apidsl for everything except the public API.
- [#1774](https://github.com/TokTok/c-toxcore/pull/1774) chore: Remove config.h.
- [#1773](https://github.com/TokTok/c-toxcore/pull/1773) chore: Fix gen-file.sh: it wasn't globbing properly.
- [#1772](https://github.com/TokTok/c-toxcore/pull/1772) chore: Add .cc files to the static analysis.
- [#1770](https://github.com/TokTok/c-toxcore/pull/1770) cleanup: merge onion.c changes from new groupchats fork
- [#1769](https://github.com/TokTok/c-toxcore/pull/1769) chore: merge tcp_connection changes from new groupchats fork
- [#1768](https://github.com/TokTok/c-toxcore/pull/1768) chore: merge DHT changes from new groupchats fork
- [#1766](https://github.com/TokTok/c-toxcore/pull/1766) chore: Use docker for the autotools ci build.
- [#1765](https://github.com/TokTok/c-toxcore/pull/1765) fix: Fix file permission issue with toxchat/bootstrap-node Docker container
- [#1762](https://github.com/TokTok/c-toxcore/pull/1762) chore: Add autotools build; exempt crypto_pwhash from tokstyle.
- [#1761](https://github.com/TokTok/c-toxcore/pull/1761) cleanup: Don't include `"config.h"` unless needed.
- [#1759](https://github.com/TokTok/c-toxcore/pull/1759) cleanup: address some unused return values
- [#1758](https://github.com/TokTok/c-toxcore/pull/1758) test: Make ERROR logging fatal in tests.
- [#1754](https://github.com/TokTok/c-toxcore/pull/1754) fix: off-by-one error caused by integer division without proper cast
- [#1753](https://github.com/TokTok/c-toxcore/pull/1753) cleanup: use crypto_memzero to wipe secret keys when no longer in use
- [#1752](https://github.com/TokTok/c-toxcore/pull/1752) chore: Use an incrementing version number for coverity scans.
- [#1751](https://github.com/TokTok/c-toxcore/pull/1751) fix: Fixed uninitialised value copy.
- [#1747](https://github.com/TokTok/c-toxcore/pull/1747) cleanup: Fix some clang-tidy warnings and make them errors.
- [#1746](https://github.com/TokTok/c-toxcore/pull/1746) chore: Add clang-tidy review github workflow.
- [#1744](https://github.com/TokTok/c-toxcore/pull/1744) cleanup: Enforce for loop consistency.
- [#1743](https://github.com/TokTok/c-toxcore/pull/1743) chore: Minor cleanups of warnings given by cppcheck.
- [#1742](https://github.com/TokTok/c-toxcore/pull/1742) test: Add a simple test for `ip_ntoa`.
- [#1740](https://github.com/TokTok/c-toxcore/pull/1740) cleanup: Put fatal errors where API return values should be impossible
- [#1738](https://github.com/TokTok/c-toxcore/pull/1738) chore: Add missing `sudo` to coverity apt-get calls.
- [#1737](https://github.com/TokTok/c-toxcore/pull/1737) refactor: Fix previous refactor
- [#1736](https://github.com/TokTok/c-toxcore/pull/1736) chore: Add workflow for running coverity scan.
- [#1735](https://github.com/TokTok/c-toxcore/pull/1735) cleanup: Use `static_assert` instead of preprocessor `#error`.
- [#1734](https://github.com/TokTok/c-toxcore/pull/1734) chore: Add logger to onion and onion announce objects
- [#1733](https://github.com/TokTok/c-toxcore/pull/1733) cleanup: Minor fixes in test code.
- [#1732](https://github.com/TokTok/c-toxcore/pull/1732) cleanup: Refactor kill_nonused_tcp()
- [#1730](https://github.com/TokTok/c-toxcore/pull/1730) cleanup: Fix last instance of `-Wcast-align` and enable the warning.
- [#1729](https://github.com/TokTok/c-toxcore/pull/1729) cleanup: Ensure that error codes are always initialised.
- [#1727](https://github.com/TokTok/c-toxcore/pull/1727) cleanup: Avoid endian-specific code in `crypto_core`.
- [#1720](https://github.com/TokTok/c-toxcore/pull/1720) feat: Add automatic fuzz testing for c-toxcore
- [#1673](https://github.com/TokTok/c-toxcore/pull/1673) cleanup: Remove hardening code from DHT
- [#1622](https://github.com/TokTok/c-toxcore/pull/1622) perf: Make the key cracker a bit faster
- [#1333](https://github.com/TokTok/c-toxcore/pull/1333) refactor: Clean up friend loading.
- [#1307](https://github.com/TokTok/c-toxcore/pull/1307) refactor: Split toxav_iterate into audio and video part

### Closed issues:

- [#1967](https://github.com/TokTok/c-toxcore/issues/1967) Potential freeing of an immutable static buffer
- [#1788](https://github.com/TokTok/c-toxcore/issues/1788) Rename dht->last_run
- [#1719](https://github.com/TokTok/c-toxcore/issues/1719) Enforce braces around macros that compute a value
- [#1694](https://github.com/TokTok/c-toxcore/issues/1694) Double unlocking in the ac_iterate
- [#1332](https://github.com/TokTok/c-toxcore/issues/1332) Padding bytes in Tox save format are not specified
- [#1217](https://github.com/TokTok/c-toxcore/issues/1217) valgrind reports "Conditional jump or move depends on uninitialised value(s)"
- [#1118](https://github.com/TokTok/c-toxcore/issues/1118) Fix threading issues in tests caught by tsan (data race etc)
- [#1087](https://github.com/TokTok/c-toxcore/issues/1087) Remove all uses of `%zu` in printf formats.
- [#1040](https://github.com/TokTok/c-toxcore/issues/1040) Random numbers should not be produced using `rng() % max`.
- [#540](https://github.com/TokTok/c-toxcore/issues/540) Stop deleting source files
- [#501](https://github.com/TokTok/c-toxcore/issues/501) Testsuite fails and hangs on FreeBSD
- [#451](https://github.com/TokTok/c-toxcore/issues/451) Don't fail when building toxcore on windows with `cmake .`
- [#350](https://github.com/TokTok/c-toxcore/issues/350) Configure coverity runs for nightly builds
- [#349](https://github.com/TokTok/c-toxcore/issues/349) Run clang-tidy on Travis with specific warnings as errors.
- [#348](https://github.com/TokTok/c-toxcore/issues/348) Run cppcheck on Travis and push the results to toktok.github.io.
- [#323](https://github.com/TokTok/c-toxcore/issues/323) Set library version on future releases
- [#235](https://github.com/TokTok/c-toxcore/issues/235) Video corruption: Don't drop video keyframes
- [#203](https://github.com/TokTok/c-toxcore/issues/203) ToxAV is still on the old API style
- [#198](https://github.com/TokTok/c-toxcore/issues/198) Crash on call while peer calling you
- [#167](https://github.com/TokTok/c-toxcore/issues/167) Const-ify pointers
- [#124](https://github.com/TokTok/c-toxcore/issues/124) Don't include OS specific headers in .h files
- [#106](https://github.com/TokTok/c-toxcore/issues/106) Sometimes Toxcore reports the wrong connection status for both the DHT, and friends.
- [#85](https://github.com/TokTok/c-toxcore/issues/85) Reproducible Builds // OBS a bad Idea

## v0.2.13

### Merged PRs:

- [#1725](https://github.com/TokTok/c-toxcore/pull/1725) cleanup: add some missing null checks
- [#1723](https://github.com/TokTok/c-toxcore/pull/1723) chore: Run infer static analyser on circle ci builds.
- [#1722](https://github.com/TokTok/c-toxcore/pull/1722) chore: Release 0.2.13
- [#1718](https://github.com/TokTok/c-toxcore/pull/1718) fix: Sec/fix crypto size compute
- [#1716](https://github.com/TokTok/c-toxcore/pull/1716) chore: Use toktok-stack docker image with built third_party.
- [#1713](https://github.com/TokTok/c-toxcore/pull/1713) test: Add some unit tests for important internal DHT functions.
- [#1708](https://github.com/TokTok/c-toxcore/pull/1708) perf: reduce calling into Mono_Time in DHT
- [#1706](https://github.com/TokTok/c-toxcore/pull/1706) chore: Enable cimple tests on cirrus build.
- [#1705](https://github.com/TokTok/c-toxcore/pull/1705) fix: issue with save_load autotest
- [#1703](https://github.com/TokTok/c-toxcore/pull/1703) chore: Upgrade to toktok-stack:0.0.11.
- [#1699](https://github.com/TokTok/c-toxcore/pull/1699) fix: some friend connection issues
- [#1698](https://github.com/TokTok/c-toxcore/pull/1698) fix: bug causing API to report wrong self connection status
- [#1693](https://github.com/TokTok/c-toxcore/pull/1693) chore: Update IRC info
- [#1691](https://github.com/TokTok/c-toxcore/pull/1691) chore: Fix Appveyor and add workarounds for Cirrus CI
- [#1686](https://github.com/TokTok/c-toxcore/pull/1686) chore: Enable c-toxcore conan packaging
- [#1684](https://github.com/TokTok/c-toxcore/pull/1684) cleanup: Update INSTALL.md instructions
- [#1679](https://github.com/TokTok/c-toxcore/pull/1679) cleanup: Trivial cleanup
- [#1674](https://github.com/TokTok/c-toxcore/pull/1674) cleanup: filetransfer code
- [#1672](https://github.com/TokTok/c-toxcore/pull/1672) docs: Add instructions for building unit tests to INSTALL.md
- [#1667](https://github.com/TokTok/c-toxcore/pull/1667) chore: Update tox-bootstrapd checksum due to newer packages in Alpine
- [#1664](https://github.com/TokTok/c-toxcore/pull/1664) cleanup: use heap memory instead of stack for large variables
- [#1663](https://github.com/TokTok/c-toxcore/pull/1663) fix: Fix file tests on windows
- [#1633](https://github.com/TokTok/c-toxcore/pull/1633) fix: AppVeyor failing due to conan remote being added twice
- [#1602](https://github.com/TokTok/c-toxcore/pull/1602) fix: Fix buffer over-read when a peer leaves a conference
- [#1586](https://github.com/TokTok/c-toxcore/pull/1586) test: Fix tcp_relay_test by adding a second bootstrap node.
- [#1580](https://github.com/TokTok/c-toxcore/pull/1580) style: Format comments according to tokstyle's requirements.
- [#1557](https://github.com/TokTok/c-toxcore/pull/1557) chore: Add conan support
- [#1537](https://github.com/TokTok/c-toxcore/pull/1537) chore: Cygwin build
- [#1516](https://github.com/TokTok/c-toxcore/pull/1516) cleanup: Make pylint and mypy happy with bootstrap_node_info.py.
- [#1515](https://github.com/TokTok/c-toxcore/pull/1515) style: Run restyled on Travis and Circle CI scripts.
- [#1514](https://github.com/TokTok/c-toxcore/pull/1514) refactor: Remove multi-declarators entirely.
- [#1513](https://github.com/TokTok/c-toxcore/pull/1513) refactor: Disallow multiple initialised declarators per decl.
- [#1510](https://github.com/TokTok/c-toxcore/pull/1510) chore: Don't build pushes to branches, only to tags.
- [#1504](https://github.com/TokTok/c-toxcore/pull/1504) chore: Remove release-drafter configuration in favour of global one.
- [#1498](https://github.com/TokTok/c-toxcore/pull/1498) refactor: Limit scope of loop iterators.
- [#1497](https://github.com/TokTok/c-toxcore/pull/1497) refactor: Use bash arrays instead of strings for static analysis scripts.
- [#1496](https://github.com/TokTok/c-toxcore/pull/1496) cleanup: Stop hard-coding packet IDs in tests.
- [#1495](https://github.com/TokTok/c-toxcore/pull/1495) chore: Exclude imported libsodium sources from restyled.
- [#1493](https://github.com/TokTok/c-toxcore/pull/1493) feat: Add logging to TCP and onion client.
- [#1489](https://github.com/TokTok/c-toxcore/pull/1489) cleanup: `NAC_LIBS` -> `NACL_LIBS`.
- [#1487](https://github.com/TokTok/c-toxcore/pull/1487) chore: Add autotools build to localbuild docker images.
- [#1473](https://github.com/TokTok/c-toxcore/pull/1473) chore: Add a script to run Travis CI locally.
- [#1467](https://github.com/TokTok/c-toxcore/pull/1467) fix: Fix a bug in savedata loading when malloc fails.
- [#1464](https://github.com/TokTok/c-toxcore/pull/1464) fix: Fix errors on error paths found by oomer.
- [#1463](https://github.com/TokTok/c-toxcore/pull/1463) cleanup: Add a check that we don't have any unused functions.
- [#1462](https://github.com/TokTok/c-toxcore/pull/1462) cleanup: Include `<string.h>` for `explicit_bzero`.
- [#1436](https://github.com/TokTok/c-toxcore/pull/1436) chore: Enable cimple tests by default but allow disabling them.

### Closed issues:

- [#1598](https://github.com/TokTok/c-toxcore/issues/1598) ERROR:  heap-buffer-overflow in group.c found with AddressSanitizer
- [#1326](https://github.com/TokTok/c-toxcore/issues/1326) the cause is great, but this thing is completely unusable
- [#1319](https://github.com/TokTok/c-toxcore/issues/1319) Is this new application is safe & trusted ??
- [#1236](https://github.com/TokTok/c-toxcore/issues/1236) Ruby Extension?
- [#1149](https://github.com/TokTok/c-toxcore/issues/1149) uTox aborts on toxcore restart
- [#886](https://github.com/TokTok/c-toxcore/issues/886) Maybe need to set the stacksize for musl-libc

## v0.2.12

### Merged PRs:

- [#1458](https://github.com/TokTok/c-toxcore/pull/1458) Release 0.2.12
- [#1457](https://github.com/TokTok/c-toxcore/pull/1457) Disable non-hermetic tests by default.
- [#1456](https://github.com/TokTok/c-toxcore/pull/1456) Limit the number of friends you can have to ~4 billion.
- [#1452](https://github.com/TokTok/c-toxcore/pull/1452) Add execution trace option for debugging.
- [#1444](https://github.com/TokTok/c-toxcore/pull/1444) Set up release-drafter to automatically draft the next release.
- [#1443](https://github.com/TokTok/c-toxcore/pull/1443) Allow test coverage to fluctuate 2% up and down, but not below 80%.
- [#1442](https://github.com/TokTok/c-toxcore/pull/1442) Add CODEOWNERS and settings.yml files.
- [#1441](https://github.com/TokTok/c-toxcore/pull/1441) [ImgBot] Optimize images
- [#1439](https://github.com/TokTok/c-toxcore/pull/1439) Fix continuous integration builds.
- [#1437](https://github.com/TokTok/c-toxcore/pull/1437) Rework the toxchat/bootstrap-node Docker image.
- [#1435](https://github.com/TokTok/c-toxcore/pull/1435) Enable TCP relay test in Bazel and autotools build.
- [#1434](https://github.com/TokTok/c-toxcore/pull/1434) Skip invalid TCP relays and DHT nodes when loading save data.
- [#1433](https://github.com/TokTok/c-toxcore/pull/1433) Fix saving of combination of loaded and connected TCP relays
- [#1430](https://github.com/TokTok/c-toxcore/pull/1430) Invert `not_valid` functions and name them `is_valid`.
- [#1429](https://github.com/TokTok/c-toxcore/pull/1429) Fix things not being initialized if creating a TCP-only network
- [#1426](https://github.com/TokTok/c-toxcore/pull/1426) Remove tokstyle exemptions from build files.
- [#1425](https://github.com/TokTok/c-toxcore/pull/1425) Stop using the "inline namespace" feature of apidsl.
- [#1424](https://github.com/TokTok/c-toxcore/pull/1424) Add new semi-private API functions to set per-packet-id custom handlers.
- [#1423](https://github.com/TokTok/c-toxcore/pull/1423) Give CI workflow a better name: clang-sanitizers
- [#1422](https://github.com/TokTok/c-toxcore/pull/1422) Use public API for sending in RTP
- [#1421](https://github.com/TokTok/c-toxcore/pull/1421) Install ci-tools and get tokstyle via the script it provides.
- [#1420](https://github.com/TokTok/c-toxcore/pull/1420) Use tox public API for sending packets in toxav BWController
- [#1419](https://github.com/TokTok/c-toxcore/pull/1419) Remove newlines from the end of LOGGER format strings.
- [#1418](https://github.com/TokTok/c-toxcore/pull/1418) Change ToxAVCall struct mutex to a more distinct name
- [#1417](https://github.com/TokTok/c-toxcore/pull/1417) Create own instance of Mono_Time for ToxAV
- [#1416](https://github.com/TokTok/c-toxcore/pull/1416) Stop using Messenger's mono_time in bandwidth controller.
- [#1415](https://github.com/TokTok/c-toxcore/pull/1415) Fix 2 memory leaks in ToxAV.
- [#1414](https://github.com/TokTok/c-toxcore/pull/1414) Show function names in asan/tsan stack traces on CircleCI.
- [#1413](https://github.com/TokTok/c-toxcore/pull/1413) Make afl_toxsave.c a bit more portable; fix memory leak.
- [#1411](https://github.com/TokTok/c-toxcore/pull/1411) Fixes towards building on MSVC.
- [#1409](https://github.com/TokTok/c-toxcore/pull/1409) Mark conference test as small.
- [#1407](https://github.com/TokTok/c-toxcore/pull/1407) Add minimal save generator
- [#1406](https://github.com/TokTok/c-toxcore/pull/1406) Migrate format-source script to new apidsl web app.
- [#1404](https://github.com/TokTok/c-toxcore/pull/1404) Smarter setup of bazel remote cache on Cirrus CI.
- [#1331](https://github.com/TokTok/c-toxcore/pull/1331) Add basic test adapter for AFL

### Closed issues:

- [#1365](https://github.com/TokTok/c-toxcore/issues/1365) Add the option to use LAN discovery even when using a proxy for remote connections
- [#1353](https://github.com/TokTok/c-toxcore/issues/1353) libtoxdns.a and libtoxav.a
- [#86](https://github.com/TokTok/c-toxcore/issues/86) Freenet as Offline Messaging Backend

## v0.2.11

### Merged PRs:

- [#1405](https://github.com/TokTok/c-toxcore/pull/1405) Release 0.2.11
- [#1403](https://github.com/TokTok/c-toxcore/pull/1403) Install libsodium from apt instead of from source.
- [#1402](https://github.com/TokTok/c-toxcore/pull/1402) Remove bazel build from Travis.
- [#1400](https://github.com/TokTok/c-toxcore/pull/1400) Disable bazel remote cache on CI.
- [#1399](https://github.com/TokTok/c-toxcore/pull/1399) Periodically try to send direct packets when connected by TCP.
- [#1398](https://github.com/TokTok/c-toxcore/pull/1398) Minor cleanup: use `assoc_timeout` function where possible.
- [#1397](https://github.com/TokTok/c-toxcore/pull/1397) Check that LOGGER macros are only called with string literals.
- [#1396](https://github.com/TokTok/c-toxcore/pull/1396) Make function defns match their decls regarding storage class.
- [#1395](https://github.com/TokTok/c-toxcore/pull/1395) Mark file-local function definitions as `static`.
- [#1394](https://github.com/TokTok/c-toxcore/pull/1394) Enable remote cache for bazel builds.
- [#1393](https://github.com/TokTok/c-toxcore/pull/1393) Add another bootstrap node to the bootstrap test.
- [#1392](https://github.com/TokTok/c-toxcore/pull/1392) Clear out old conference connections.
- [#1391](https://github.com/TokTok/c-toxcore/pull/1391) Minor cleanups in network code.
- [#1390](https://github.com/TokTok/c-toxcore/pull/1390) Avoid casting back and forth between void-ptr.
- [#1389](https://github.com/TokTok/c-toxcore/pull/1389) Standardise on having a comma at the end of enums.
- [#1388](https://github.com/TokTok/c-toxcore/pull/1388) Fix up comments a bit to start being more uniform.
- [#1387](https://github.com/TokTok/c-toxcore/pull/1387) Use rules_cc instead of native cc_library rules.
- [#1386](https://github.com/TokTok/c-toxcore/pull/1386) Use spdx license identifier instead of GPL blurb.
- [#1383](https://github.com/TokTok/c-toxcore/pull/1383) Pass packet ID to custom packet handlers.
- [#1382](https://github.com/TokTok/c-toxcore/pull/1382) Add a mutex lock/unlock inside every public API function.
- [#1381](https://github.com/TokTok/c-toxcore/pull/1381) Use `net_pack` instead of casting bytes to ints.
- [#1380](https://github.com/TokTok/c-toxcore/pull/1380) Disable FreeBSD travis build until it is fixed.
- [#1379](https://github.com/TokTok/c-toxcore/pull/1379) Update and fix FreeBSD setup on Travis-CI
- [#1378](https://github.com/TokTok/c-toxcore/pull/1378) Use ninja build system for the cmake-linux build.
- [#1376](https://github.com/TokTok/c-toxcore/pull/1376) Remove testing/av_test.c.
- [#1375](https://github.com/TokTok/c-toxcore/pull/1375) Add "cimple_test" to the bazel build.
- [#1374](https://github.com/TokTok/c-toxcore/pull/1374) Handle invite to existing conference
- [#1372](https://github.com/TokTok/c-toxcore/pull/1372) Upgrade bazel to 2.1.1.
- [#1371](https://github.com/TokTok/c-toxcore/pull/1371) Bump to astyle-3.1 in travis build.
- [#1370](https://github.com/TokTok/c-toxcore/pull/1370) use -1 rather than ~0 in unsigned integer types
- [#1362](https://github.com/TokTok/c-toxcore/pull/1362) Workaround for message number saving
- [#1358](https://github.com/TokTok/c-toxcore/pull/1358) Allow Bazel to rerun tests marked as flaky
- [#1352](https://github.com/TokTok/c-toxcore/pull/1352) Update tests to use a working bootstrap node
- [#1349](https://github.com/TokTok/c-toxcore/pull/1349) Fix tox-bootstrapd's README and update Dockerfile
- [#1347](https://github.com/TokTok/c-toxcore/pull/1347) Fix pthread_mutex_destroy getting too many arguments
- [#1346](https://github.com/TokTok/c-toxcore/pull/1346) Fix most TSAN failures
- [#1345](https://github.com/TokTok/c-toxcore/pull/1345) fix concurrency issues in mono_time
- [#1343](https://github.com/TokTok/c-toxcore/pull/1343) Fix TSAN failures in tests
- [#1334](https://github.com/TokTok/c-toxcore/pull/1334) fix missing group title length check
- [#1330](https://github.com/TokTok/c-toxcore/pull/1330) Force IPv4 for cirrus-ci tests
- [#1329](https://github.com/TokTok/c-toxcore/pull/1329) bump libsodium version in appveyor.yml
- [#1322](https://github.com/TokTok/c-toxcore/pull/1322) Clean-up of group.c code
- [#1321](https://github.com/TokTok/c-toxcore/pull/1321) Some small fixes to groups.
- [#1299](https://github.com/TokTok/c-toxcore/pull/1299) Add VScode folder to .gitignore
- [#1297](https://github.com/TokTok/c-toxcore/pull/1297) Use net_pack/unpack instead of host_to_net.

### Closed issues:

- [#1373](https://github.com/TokTok/c-toxcore/issues/1373) handle crashes after group invites
- [#1368](https://github.com/TokTok/c-toxcore/issues/1368) Are tox clients also open source
- [#1366](https://github.com/TokTok/c-toxcore/issues/1366) Generate a link for websites (Friendship and proxy)
- [#1354](https://github.com/TokTok/c-toxcore/issues/1354) Unstable Tests
- [#1316](https://github.com/TokTok/c-toxcore/issues/1316) Documentation claims toxav_iteration_interval is threadsafe but it's not
- [#1274](https://github.com/TokTok/c-toxcore/issues/1274) build error
- [#850](https://github.com/TokTok/c-toxcore/issues/850) GPG App Usage

## v0.2.10

### Merged PRs:

- [#1324](https://github.com/TokTok/c-toxcore/pull/1324) Release 0.2.10
- [#1320](https://github.com/TokTok/c-toxcore/pull/1320) add undef guard in tox_many_tcp_test
- [#1314](https://github.com/TokTok/c-toxcore/pull/1314) Fix bazel build version at 0.22.0 for CI.
- [#1311](https://github.com/TokTok/c-toxcore/pull/1311) Disable failing TCP server test
- [#1310](https://github.com/TokTok/c-toxcore/pull/1310) Do not send the same packet to the same node twice
- [#1309](https://github.com/TokTok/c-toxcore/pull/1309) add configurable limit on number of stored frozen peers
- [#1305](https://github.com/TokTok/c-toxcore/pull/1305) Expose api functions for enabling and disabling AV in AV groups
- [#1302](https://github.com/TokTok/c-toxcore/pull/1302) Specify that buffer size for tox_conference_peer_get_name is given by $size

### Closed issues:

- [#1325](https://github.com/TokTok/c-toxcore/issues/1325) Question: ETA of v0.2.10?
- [#1313](https://github.com/TokTok/c-toxcore/issues/1313) CirrusCI is failing and blocking PRs
- [#1312](https://github.com/TokTok/c-toxcore/issues/1312) Onion client review
- [#1306](https://github.com/TokTok/c-toxcore/issues/1306) Persistent conference's offline peer list always grows and never decreases
- [#1303](https://github.com/TokTok/c-toxcore/issues/1303) Loaded persistent groups fail to send audio
- [#1298](https://github.com/TokTok/c-toxcore/issues/1298) How to make libtox4j-c.so for android?
- [#1261](https://github.com/TokTok/c-toxcore/issues/1261) Bump so version
- [#1116](https://github.com/TokTok/c-toxcore/issues/1116) Message length is too large log spam

## v0.2.9

### Merged PRs:

- [#1296](https://github.com/TokTok/c-toxcore/pull/1296) Add some const qualifiers
- [#1295](https://github.com/TokTok/c-toxcore/pull/1295) Implement all min/max functions for (un)signed int types.
- [#1293](https://github.com/TokTok/c-toxcore/pull/1293) Fix misaligned 4-byte access in trace logging.
- [#1291](https://github.com/TokTok/c-toxcore/pull/1291) Use correct path to test log to cat on error.
- [#1290](https://github.com/TokTok/c-toxcore/pull/1290) Display build log for autotools build on failure.
- [#1289](https://github.com/TokTok/c-toxcore/pull/1289) Enable auto tests under STRICT_ABI if static libs are available.
- [#1288](https://github.com/TokTok/c-toxcore/pull/1288) Add MIN_LOGGER_LEVEL to the Circle CI builds.
- [#1287](https://github.com/TokTok/c-toxcore/pull/1287) Avoid sending group messages to a peer before we have its group number
- [#1284](https://github.com/TokTok/c-toxcore/pull/1284) Use new WineHQ Debian package repository key
- [#1283](https://github.com/TokTok/c-toxcore/pull/1283) Release 0.2.9
- [#1282](https://github.com/TokTok/c-toxcore/pull/1282) Merge irungentoo/master back into toktok/master.
- [#1281](https://github.com/TokTok/c-toxcore/pull/1281) Allow unauthenticated wine packages in the Windows build.
- [#1278](https://github.com/TokTok/c-toxcore/pull/1278) Add cmake option for building additional tests
- [#1277](https://github.com/TokTok/c-toxcore/pull/1277) Define tox_conference_id_size and tox_conference_uid_size
- [#1273](https://github.com/TokTok/c-toxcore/pull/1273) Avoid format truncation in save compatibility test
- [#1272](https://github.com/TokTok/c-toxcore/pull/1272) Upgrade bazel to 0.19.0 to fix the bazel build.
- [#1271](https://github.com/TokTok/c-toxcore/pull/1271) Return TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION if we are not connected to any peers
- [#1268](https://github.com/TokTok/c-toxcore/pull/1268) Fix indices calculation for congestion control.
- [#1267](https://github.com/TokTok/c-toxcore/pull/1267) Improve handling of peers entering and leaving conferences
- [#1266](https://github.com/TokTok/c-toxcore/pull/1266) Expose offline conference peers in API
- [#1242](https://github.com/TokTok/c-toxcore/pull/1242) Fix critical stack overflow arising from VLA usage
- [#1239](https://github.com/TokTok/c-toxcore/pull/1239) Add some hopefully helpful documentation to the functions in mono_time.h
- [#1235](https://github.com/TokTok/c-toxcore/pull/1235) Change method of PK production for FAKE friend in DHT
- [#1234](https://github.com/TokTok/c-toxcore/pull/1234) Increase NOFILE limit for tox-bootstrapd
- [#1231](https://github.com/TokTok/c-toxcore/pull/1231) Use `bool` for IPv6 flag in test programs and `DHT_bootstrap`.
- [#1230](https://github.com/TokTok/c-toxcore/pull/1230) Add `LOGGER_ASSERT` for checking fatal error conditions.
- [#1229](https://github.com/TokTok/c-toxcore/pull/1229) Include `CTest` in CMakeLists.txt to get valgrind support.
- [#1228](https://github.com/TokTok/c-toxcore/pull/1228) Consistently use camel case enum names.
- [#1223](https://github.com/TokTok/c-toxcore/pull/1223) Add AUTOTEST option to CMakeLists.txt
- [#1221](https://github.com/TokTok/c-toxcore/pull/1221) Make tox-bootstrapd free memory on SIGINT and SIGTERM
- [#1218](https://github.com/TokTok/c-toxcore/pull/1218) Support DragonFlyBSD and prune unused variables.
- [#1215](https://github.com/TokTok/c-toxcore/pull/1215) Ensure save data unchanged after save and load
- [#1213](https://github.com/TokTok/c-toxcore/pull/1213) Make saving and loading the responsibility of Tox rather than Messenger
- [#1211](https://github.com/TokTok/c-toxcore/pull/1211) Some improvements to tox-bootstrapd's Dockerfile
- [#1210](https://github.com/TokTok/c-toxcore/pull/1210) Remove Alpine Linux bootstrap daemon dockerfile.
- [#1209](https://github.com/TokTok/c-toxcore/pull/1209) Improve Windows compatibility of toxav code.
- [#1206](https://github.com/TokTok/c-toxcore/pull/1206) Add LAN_discovery to the list of apidsl-generated files.
- [#1156](https://github.com/TokTok/c-toxcore/pull/1156) conferences saving

### Closed issues:

- [#1285](https://github.com/TokTok/c-toxcore/issues/1285) Persistent group titles get mixed up
- [#1276](https://github.com/TokTok/c-toxcore/issues/1276) How to run test case?
- [#1275](https://github.com/TokTok/c-toxcore/issues/1275) Save file corruption
- [#1269](https://github.com/TokTok/c-toxcore/issues/1269) Tox conference connected callback isn't triggered
- [#1264](https://github.com/TokTok/c-toxcore/issues/1264) tox_conference_id_size() symbol missing
- [#1262](https://github.com/TokTok/c-toxcore/issues/1262) Fails to build with STRICT_ABI option
- [#1169](https://github.com/TokTok/c-toxcore/issues/1169) PK should not be generated with random_bytes
- [#1143](https://github.com/TokTok/c-toxcore/issues/1143) Test #1081
- [#956](https://github.com/TokTok/c-toxcore/issues/956) friendlist access (add, delete, ...) causes crashes sometimes
- [#777](https://github.com/TokTok/c-toxcore/issues/777) Proposal: TFCL [Tox Friend Capabilities Level]
- [#762](https://github.com/TokTok/c-toxcore/issues/762) packet ranges not very clearly explained
- [#743](https://github.com/TokTok/c-toxcore/issues/743) Proposal: reduce Video corruption even more by negotating the reference frame between sender and receiver
- [#735](https://github.com/TokTok/c-toxcore/issues/735) Proposal: Tox MessageV2
- [#663](https://github.com/TokTok/c-toxcore/issues/663) libvpx vulnerability
- [#626](https://github.com/TokTok/c-toxcore/issues/626) please add documentation to: bwcontroller.c
- [#625](https://github.com/TokTok/c-toxcore/issues/625) function names misleading in ToxAV
- [#617](https://github.com/TokTok/c-toxcore/issues/617) WIP: ToxIdenticon - howto
- [#610](https://github.com/TokTok/c-toxcore/issues/610) PACKET_LOSSY_AV_RESERVED 8 # why?
- [#609](https://github.com/TokTok/c-toxcore/issues/609) payload_type hardcoded
- [#589](https://github.com/TokTok/c-toxcore/issues/589) running a normal tox node as tcp relay is not possible
- [#584](https://github.com/TokTok/c-toxcore/issues/584) [INFO]: network graphs 0.1.9 vs 0.1.10
- [#548](https://github.com/TokTok/c-toxcore/issues/548) toxcore removes message receipts and filetransfers from memory, when client has short network outage
- [#375](https://github.com/TokTok/c-toxcore/issues/375) Invalid bit rate prevents call

## v0.2.8

### Merged PRs:

- [#1225](https://github.com/TokTok/c-toxcore/pull/1225) Release 0.2.8
- [#1224](https://github.com/TokTok/c-toxcore/pull/1224) Avoid use of IPv6 in tests if not supported (e.g. on Travis).
- [#1216](https://github.com/TokTok/c-toxcore/pull/1216) Fix memory leak in tcp server by wiping priority queues on deletion.
- [#1212](https://github.com/TokTok/c-toxcore/pull/1212) Fix logger level defaulting to TRACE in CMake
- [#1208](https://github.com/TokTok/c-toxcore/pull/1208) Remove a function-like macro and replace it with a function.
- [#1205](https://github.com/TokTok/c-toxcore/pull/1205) Use a working DHT node for bootstrap tests.
- [#1203](https://github.com/TokTok/c-toxcore/pull/1203) Revert "Improve cmake build for MSVC."
- [#1202](https://github.com/TokTok/c-toxcore/pull/1202) Reset onion search rate for a friend when we see evidence that they are online
- [#1199](https://github.com/TokTok/c-toxcore/pull/1199) Run tests on Appveyor (Windows native build).
- [#1198](https://github.com/TokTok/c-toxcore/pull/1198) Add Cirrus CI configuration.
- [#1197](https://github.com/TokTok/c-toxcore/pull/1197) Use new `@pthread` library from toktok-stack for Windows compat.
- [#1196](https://github.com/TokTok/c-toxcore/pull/1196) Run UBSAN (undefined behaviour sanitizer) on Circle CI.
- [#1195](https://github.com/TokTok/c-toxcore/pull/1195) Fix using uninitialized mutex on call end
- [#1192](https://github.com/TokTok/c-toxcore/pull/1192) Send rejoin packets on conference disconnection
- [#1191](https://github.com/TokTok/c-toxcore/pull/1191) Improve cmake build for MSVC
- [#1188](https://github.com/TokTok/c-toxcore/pull/1188) Fix yamllint test (it's gone from bazel, add a new one).
- [#1187](https://github.com/TokTok/c-toxcore/pull/1187) Fix typos in comments and log and test assertion messages.
- [#1165](https://github.com/TokTok/c-toxcore/pull/1165) Fixed a silly boolean practice using uint8_t
- [#1164](https://github.com/TokTok/c-toxcore/pull/1164) Format yaml files according to yamllint's requirements and remove branch filter for appveyor.
- [#1161](https://github.com/TokTok/c-toxcore/pull/1161) Use most recent version of Bazel (0.17.1).
- [#1158](https://github.com/TokTok/c-toxcore/pull/1158) Use C++ style casts in C++ code.
- [#1157](https://github.com/TokTok/c-toxcore/pull/1157) Use run_auto_test fixture in typing_test.c
- [#1155](https://github.com/TokTok/c-toxcore/pull/1155) Standardise header guards.
- [#1154](https://github.com/TokTok/c-toxcore/pull/1154) Assert that we don't kill tox before killing toxav.
- [#1153](https://github.com/TokTok/c-toxcore/pull/1153) Always use the passed logger (from Messenger) in msi_kill.
- [#1151](https://github.com/TokTok/c-toxcore/pull/1151) Fix typo: tcp_replays -> tcp_relays.
- [#1150](https://github.com/TokTok/c-toxcore/pull/1150) Use `(void)` for empty parameter lists in C.
- [#1147](https://github.com/TokTok/c-toxcore/pull/1147) Ignore "unused-result" warning in super_donators code.
- [#1145](https://github.com/TokTok/c-toxcore/pull/1145) Fix login issue on Travis-CI FreeBSD build
- [#1141](https://github.com/TokTok/c-toxcore/pull/1141) Include necessary opencv2 header on OSX.
- [#1140](https://github.com/TokTok/c-toxcore/pull/1140) Clean up `add_to_list` function a bit.
- [#1139](https://github.com/TokTok/c-toxcore/pull/1139) Avoid recursion in `ip_is_lan` and `ip_is_local`.
- [#1138](https://github.com/TokTok/c-toxcore/pull/1138) Add tool to find directly recursive calls in toxcore.
- [#1136](https://github.com/TokTok/c-toxcore/pull/1136) Remove the use of `CLOCK_MONOTONIC_RAW`.
- [#1135](https://github.com/TokTok/c-toxcore/pull/1135) Avoid use of global mutable state in mono_time on win32.
- [#1134](https://github.com/TokTok/c-toxcore/pull/1134) Use `code font` for tool names and flags in INSTALL.md.
- [#1126](https://github.com/TokTok/c-toxcore/pull/1126) Simplify configure.ac for faster autotools build.
- [#1095](https://github.com/TokTok/c-toxcore/pull/1095) Use test clock in run_auto_test tests and dht test
- [#1069](https://github.com/TokTok/c-toxcore/pull/1069) Add mechanism for recovering from disconnections in conferences
- [#1046](https://github.com/TokTok/c-toxcore/pull/1046) Finish the messenger state plugin system
- [#895](https://github.com/TokTok/c-toxcore/pull/895) Feature bootstrap trace/debug log output

### Closed issues:

- [#1214](https://github.com/TokTok/c-toxcore/issues/1214) Massive red shutdown of nodes
- [#1201](https://github.com/TokTok/c-toxcore/issues/1201) Windows cross-compilation is broken
- [#1194](https://github.com/TokTok/c-toxcore/issues/1194) Cancelling unanswered toxav call locks uninitialied mutex
- [#961](https://github.com/TokTok/c-toxcore/issues/961) Can't send messages in persistent group chat
- [#960](https://github.com/TokTok/c-toxcore/issues/960) Persistent groups don't work properly when using toxync bot
- [#838](https://github.com/TokTok/c-toxcore/issues/838) How to get groupchat identifier?

## v0.2.7

### Merged PRs:

- [#1142](https://github.com/TokTok/c-toxcore/pull/1142) Release 0.2.7
- [#1137](https://github.com/TokTok/c-toxcore/pull/1137) Make `ip_is_lan` return bool instead of 0/-1.
- [#1133](https://github.com/TokTok/c-toxcore/pull/1133) Make the tsan build fail instead of swallowing its errors.
- [#1132](https://github.com/TokTok/c-toxcore/pull/1132) Use `bool` in place of 0/1 int values.
- [#1131](https://github.com/TokTok/c-toxcore/pull/1131) Format crypto_core.c.
- [#1130](https://github.com/TokTok/c-toxcore/pull/1130) Fix test class name for mono_time_test.
- [#1129](https://github.com/TokTok/c-toxcore/pull/1129) Call `abort` instead of `exit` on test failure.
- [#1128](https://github.com/TokTok/c-toxcore/pull/1128) Add some tests for `ping_array`.
- [#1127](https://github.com/TokTok/c-toxcore/pull/1127) Update copyright to 2018.
- [#1125](https://github.com/TokTok/c-toxcore/pull/1125) Run save_compatibility_test in the autotools build.
- [#1124](https://github.com/TokTok/c-toxcore/pull/1124) Fix the `PORT_ALLOC` failure of `save_compatibility_test`.
- [#1123](https://github.com/TokTok/c-toxcore/pull/1123) Add support for setting a custom monotonic time function in mono_time
- [#1122](https://github.com/TokTok/c-toxcore/pull/1122) Run all tests (and compilation) in parallel with autotools.
- [#1120](https://github.com/TokTok/c-toxcore/pull/1120) Stop using massive macros in `toxav_basic_test`.
- [#1119](https://github.com/TokTok/c-toxcore/pull/1119) Use do-while instead of while in tests.
- [#1117](https://github.com/TokTok/c-toxcore/pull/1117) Fix leave callback calling in del_groupchat
- [#1112](https://github.com/TokTok/c-toxcore/pull/1112) Fix auto_tests Makefile
- [#1110](https://github.com/TokTok/c-toxcore/pull/1110) Add check to make sure tox was created successfully
- [#1109](https://github.com/TokTok/c-toxcore/pull/1109) Consistently use 'mono_time' rather than 'monotime'
- [#1107](https://github.com/TokTok/c-toxcore/pull/1107) Always print output on failure in cmake tests on Travis.
- [#1106](https://github.com/TokTok/c-toxcore/pull/1106) Fix libmisc_tools building
- [#1104](https://github.com/TokTok/c-toxcore/pull/1104) Avoid redefining macros from different files.
- [#1103](https://github.com/TokTok/c-toxcore/pull/1103) Upload coverage to codecov as well as coveralls.
- [#1102](https://github.com/TokTok/c-toxcore/pull/1102) Enable color diagnostics on circleci.
- [#1101](https://github.com/TokTok/c-toxcore/pull/1101) Make the save_compatibility_test work with bazel.
- [#1100](https://github.com/TokTok/c-toxcore/pull/1100) Make Mono_Time an argument to current_time_monotonic
- [#1099](https://github.com/TokTok/c-toxcore/pull/1099) Fix const cast in save-generator.
- [#1098](https://github.com/TokTok/c-toxcore/pull/1098) Run both asan and tsan on Circle CI.
- [#1097](https://github.com/TokTok/c-toxcore/pull/1097) Run project tests like yamllint_test.
- [#1096](https://github.com/TokTok/c-toxcore/pull/1096) Enable .travis.yml check and use non-markdown license.
- [#1094](https://github.com/TokTok/c-toxcore/pull/1094) Set `_POSIX_C_SOURCE` to 200112L. We need it for C99 compat.
- [#1092](https://github.com/TokTok/c-toxcore/pull/1092) Install the `DHT_bootstrap` binary on `make install`.
- [#1086](https://github.com/TokTok/c-toxcore/pull/1086) Try ipv6 connections even after udp timeout
- [#1081](https://github.com/TokTok/c-toxcore/pull/1081) Change while-loop to for-loop to express for-each-frame.
- [#1075](https://github.com/TokTok/c-toxcore/pull/1075) Fix FreeBSD VM on Travis not shutting down
- [#1061](https://github.com/TokTok/c-toxcore/pull/1061) Force storing the result of crypto_memcmp in the test.
- [#1057](https://github.com/TokTok/c-toxcore/pull/1057) Reduce the number of times `unix_time_update` is called.
- [#1051](https://github.com/TokTok/c-toxcore/pull/1051) Add save file generator, compatibility test, and generate a savefile
- [#1038](https://github.com/TokTok/c-toxcore/pull/1038) Use per-instance `Mono_Time` instead of a global `unix_time`

### Closed issues:

- [#1114](https://github.com/TokTok/c-toxcore/issues/1114) Segfault on group quit, free of invalid audio_decoder
- [#1105](https://github.com/TokTok/c-toxcore/issues/1105) Sodium.h missing?

## v0.2.6

### Merged PRs:

- [#1093](https://github.com/TokTok/c-toxcore/pull/1093) Release 0.2.6
- [#1090](https://github.com/TokTok/c-toxcore/pull/1090) Fix possible resource leaks in test
- [#1089](https://github.com/TokTok/c-toxcore/pull/1089) Limit the size of a save file in file_saving_test.
- [#1088](https://github.com/TokTok/c-toxcore/pull/1088) Use `--config` to tell bazel about the environment.
- [#1085](https://github.com/TokTok/c-toxcore/pull/1085) Prune long long warnings.
- [#1084](https://github.com/TokTok/c-toxcore/pull/1084) Fix style in toxav.c.
- [#1083](https://github.com/TokTok/c-toxcore/pull/1083) Fix coding style in rtp module.
- [#1082](https://github.com/TokTok/c-toxcore/pull/1082) Fix groupav.c style and avoid casts in toxav_old.c.
- [#1080](https://github.com/TokTok/c-toxcore/pull/1080) Fix memory leak in error path in group A/V.
- [#1079](https://github.com/TokTok/c-toxcore/pull/1079) Fix style in video.c.
- [#1078](https://github.com/TokTok/c-toxcore/pull/1078) Fix style in msi.c.
- [#1077](https://github.com/TokTok/c-toxcore/pull/1077) Make `conferences_object` properly typed.
- [#1076](https://github.com/TokTok/c-toxcore/pull/1076) Fix style in bwcontroller module.
- [#1074](https://github.com/TokTok/c-toxcore/pull/1074) Move OSX to stage 1 of Travis.
- [#1073](https://github.com/TokTok/c-toxcore/pull/1073) Stop running tests in the bazel build.
- [#1072](https://github.com/TokTok/c-toxcore/pull/1072) Avoid forward declaration of rtp structs.
- [#1071](https://github.com/TokTok/c-toxcore/pull/1071) Temporarily disable FreeBSD build, since it times out.
- [#1070](https://github.com/TokTok/c-toxcore/pull/1070) Fix enumerator names in toxav to comply with toxcore naming standards.
- [#1068](https://github.com/TokTok/c-toxcore/pull/1068) Fix a few warnings from clang.
- [#1067](https://github.com/TokTok/c-toxcore/pull/1067) Remove last use of the `MIN` macro.
- [#1066](https://github.com/TokTok/c-toxcore/pull/1066) Remove all uses of the PAIR macro in toxav.
- [#1064](https://github.com/TokTok/c-toxcore/pull/1064) Fix ToxAv's use of `struct Tox`.
- [#1063](https://github.com/TokTok/c-toxcore/pull/1063) Avoid passing -1 as friend connection to new groups.
- [#1062](https://github.com/TokTok/c-toxcore/pull/1062) Check that the save file size isn't larger than our address space.
- [#1060](https://github.com/TokTok/c-toxcore/pull/1060) Avoid implicit conversion of negative value to uint32_t.
- [#1059](https://github.com/TokTok/c-toxcore/pull/1059) Assert that we don't divide by 0 in random_testing.cc.
- [#1056](https://github.com/TokTok/c-toxcore/pull/1056) Fix typo in loop over assocs.
- [#1053](https://github.com/TokTok/c-toxcore/pull/1053) Use tokstyle in the cmake travis build.
- [#1049](https://github.com/TokTok/c-toxcore/pull/1049) Fix some printf format specifiers.
- [#1043](https://github.com/TokTok/c-toxcore/pull/1043) Add simple deterministic random number generator for tests
- [#1042](https://github.com/TokTok/c-toxcore/pull/1042) Add callback for successful connection to a conference
- [#1039](https://github.com/TokTok/c-toxcore/pull/1039) Use the crypto random functions instead of `rand()`.
- [#1036](https://github.com/TokTok/c-toxcore/pull/1036) Add deprecation notice to some UPPER_CASE enums.
- [#1016](https://github.com/TokTok/c-toxcore/pull/1016) Split out conference type (text/av) from identifier.

## v0.2.5

### Merged PRs:

- [#1054](https://github.com/TokTok/c-toxcore/pull/1054) Release 0.2.5
- [#1048](https://github.com/TokTok/c-toxcore/pull/1048) Fix error message in m_send_generic_message
- [#1047](https://github.com/TokTok/c-toxcore/pull/1047) Remove unused `m_callback_log` function.
- [#1041](https://github.com/TokTok/c-toxcore/pull/1041) Avoid multiple for-next expressions.
- [#1037](https://github.com/TokTok/c-toxcore/pull/1037) Run all tests in the Autotools build
- [#1035](https://github.com/TokTok/c-toxcore/pull/1035) Fix problems with initial connections and name-setting in conferences
- [#1032](https://github.com/TokTok/c-toxcore/pull/1032) Use auto_test fixture in some tests and standardise filenames
- [#1030](https://github.com/TokTok/c-toxcore/pull/1030) Make a separate `struct Tox` containing the Messenger.
- [#1029](https://github.com/TokTok/c-toxcore/pull/1029) Add `by_id` and `get_id` functions, renaming from `*_uid`.
- [#1025](https://github.com/TokTok/c-toxcore/pull/1025) More fixed_width ints and incorporating file_saving_test.c
- [#1023](https://github.com/TokTok/c-toxcore/pull/1023) Run buildifier on c-toxcore BUILD files.
- [#1022](https://github.com/TokTok/c-toxcore/pull/1022) Make `resize` in `list.c` return bool instead of 0/1.
- [#1021](https://github.com/TokTok/c-toxcore/pull/1021) Remove redundant casts to the same type.
- [#1020](https://github.com/TokTok/c-toxcore/pull/1020) Add github usernames to TODOs.
- [#1019](https://github.com/TokTok/c-toxcore/pull/1019) Synchronise parameter names in headers with those in the implementation.
- [#1018](https://github.com/TokTok/c-toxcore/pull/1018) Reduce nesting by doing more early returns on error.
- [#1017](https://github.com/TokTok/c-toxcore/pull/1017) Add missing braces in dht_test.c.
- [#1011](https://github.com/TokTok/c-toxcore/pull/1011) Run Clang global static analysis on Travis.
- [#1010](https://github.com/TokTok/c-toxcore/pull/1010) Avoid implementations in .h files or #including .c files.

### Closed issues:

- [#1028](https://github.com/TokTok/c-toxcore/issues/1028) qTox crashes 1-2 times a day after update to 0.2.4
- [#1002](https://github.com/TokTok/c-toxcore/issues/1002) Implement an abstraction over pthread and windows thread synchronisation primitives

## v0.2.4

### Merged PRs:

- [#1024](https://github.com/TokTok/c-toxcore/pull/1024) Release v0.2.4
- [#1014](https://github.com/TokTok/c-toxcore/pull/1014) Use string comparison operator in configure.ac.
- [#1013](https://github.com/TokTok/c-toxcore/pull/1013) Link -lsocket and -lnsl for socket functions on Solaris.
- [#1012](https://github.com/TokTok/c-toxcore/pull/1012) Correct the max hostname length constant.
- [#1009](https://github.com/TokTok/c-toxcore/pull/1009) Using stdint instead of int/long
- [#1008](https://github.com/TokTok/c-toxcore/pull/1008) Set `_XOPEN_SOURCE` to 700 for FreeBSD.
- [#1007](https://github.com/TokTok/c-toxcore/pull/1007) Use enums for group packet types.
- [#1006](https://github.com/TokTok/c-toxcore/pull/1006) Set C++11/C99 flag manually in older cmake on not-msvc.
- [#1005](https://github.com/TokTok/c-toxcore/pull/1005) Use the correct repository name in the coverage badge.
- [#1003](https://github.com/TokTok/c-toxcore/pull/1003) Remove LOGGER_ERROR for harmless send failure.
- [#1001](https://github.com/TokTok/c-toxcore/pull/1001) Add conference_by_uid and conference_get_uid functions.
- [#1000](https://github.com/TokTok/c-toxcore/pull/1000) Limit number of group chats to 65536.
- [#998](https://github.com/TokTok/c-toxcore/pull/998) Use named function types for group callbacks.
- [#997](https://github.com/TokTok/c-toxcore/pull/997) Style fixes in TCP code; remove MIN and PAIR from util.h.
- [#996](https://github.com/TokTok/c-toxcore/pull/996) Add the bazel build as one of the PR blocking builds.
- [#995](https://github.com/TokTok/c-toxcore/pull/995) Fix style in some header files.
- [#994](https://github.com/TokTok/c-toxcore/pull/994) Fix style in DHT.c.
- [#993](https://github.com/TokTok/c-toxcore/pull/993) Move `load_state` and its helper functions to their own module.
- [#991](https://github.com/TokTok/c-toxcore/pull/991) Use named function types for friend_connection callbacks.
- [#990](https://github.com/TokTok/c-toxcore/pull/990) Use named function types for friend_requests callbacks.
- [#989](https://github.com/TokTok/c-toxcore/pull/989) Use named function types for callbacks in net_crypto.
- [#987](https://github.com/TokTok/c-toxcore/pull/987) Use named types for onion callbacks.
- [#986](https://github.com/TokTok/c-toxcore/pull/986) Simplify Travis-CI FreeBSD build
- [#985](https://github.com/TokTok/c-toxcore/pull/985) Clarify the intent of "file kinds" in the API.
- [#984](https://github.com/TokTok/c-toxcore/pull/984) Avoid side-effectful assignments in conditionals.
- [#981](https://github.com/TokTok/c-toxcore/pull/981) Factor out time keeping code into its own module: mono_time.c.
- [#979](https://github.com/TokTok/c-toxcore/pull/979) Add a thread-safe version of unix_time and friends.
- [#978](https://github.com/TokTok/c-toxcore/pull/978) Rename `BS_LIST` to `BS_List` to follow the naming conventions.
- [#977](https://github.com/TokTok/c-toxcore/pull/977) Remove VLA usage from `send_audio_packet`.
- [#976](https://github.com/TokTok/c-toxcore/pull/976) Call the "peer leaves" callback only once on group delete.
- [#975](https://github.com/TokTok/c-toxcore/pull/975) Factor out the actual test code from conference_test.
- [#972](https://github.com/TokTok/c-toxcore/pull/972) Add a test that reproduces the NULL peer nick bug.
- [#968](https://github.com/TokTok/c-toxcore/pull/968) Make tox.c unambiguously parseable.
- [#967](https://github.com/TokTok/c-toxcore/pull/967) lan_discovery_test and version_test cleanup
- [#966](https://github.com/TokTok/c-toxcore/pull/966) Use run_auto_test.h test fixture for some auto-tests.
- [#965](https://github.com/TokTok/c-toxcore/pull/965) Add `#include <cstdio>` for `std::printf`.
- [#964](https://github.com/TokTok/c-toxcore/pull/964) Add some tests for our ring_buffer implementation.
- [#962](https://github.com/TokTok/c-toxcore/pull/962) Collect `PACKET_ID*` constants in `net_crypto.h`, cleanup their uses
- [#958](https://github.com/TokTok/c-toxcore/pull/958) Fix leak of Logger instances in dht_test.
- [#957](https://github.com/TokTok/c-toxcore/pull/957) Remove broken conference tests.
- [#955](https://github.com/TokTok/c-toxcore/pull/955) Another TCP_test upgrade
- [#954](https://github.com/TokTok/c-toxcore/pull/954) Proposal: Make arg `host` understand clearly.
- [#953](https://github.com/TokTok/c-toxcore/pull/953) Add missing MAX_HOSTNAME_LENGTH doc.
- [#945](https://github.com/TokTok/c-toxcore/pull/945) Add a test to try and overflow the send queue in net_crypto.
- [#943](https://github.com/TokTok/c-toxcore/pull/943) Correct check for net_crypto packet index.
- [#942](https://github.com/TokTok/c-toxcore/pull/942) Simplify Travis CI builds.
- [#932](https://github.com/TokTok/c-toxcore/pull/932) Various minor cleanups in `net_crypto`.

### Closed issues:

- [#1015](https://github.com/TokTok/c-toxcore/issues/1015) Improve Solaris support
- [#1004](https://github.com/TokTok/c-toxcore/issues/1004) qTox: "Program received signal SIGPIPE, Broken pipe." with TokTok-c-toxcore-v0.2.3_GH0 on FreeBSD 11.x.
- [#988](https://github.com/TokTok/c-toxcore/issues/988) Registration on https://nodes.tox.chat (question)
- [#982](https://github.com/TokTok/c-toxcore/issues/982) Merge the two travis stages for freebsd back into one
- [#970](https://github.com/TokTok/c-toxcore/issues/970) Crash with persistent groups
- [#963](https://github.com/TokTok/c-toxcore/issues/963) ToxAV's `rb_write` function is written in a strange way
- [#946](https://github.com/TokTok/c-toxcore/issues/946) [API] for max proxy address length
- [#944](https://github.com/TokTok/c-toxcore/issues/944) How detect that friend is busy
- [#936](https://github.com/TokTok/c-toxcore/issues/936) Help needed in testing a tox client,I need some dummy toxids to test .
- [#923](https://github.com/TokTok/c-toxcore/issues/923) Crash on malloc in ping_array_add
- [#911](https://github.com/TokTok/c-toxcore/issues/911) Weekly Tox Dev Meeting
- [#910](https://github.com/TokTok/c-toxcore/issues/910) Crash in clear_entry in ping_array.c
- [#903](https://github.com/TokTok/c-toxcore/issues/903) c-toxcore and LGPL (question)
- [#528](https://github.com/TokTok/c-toxcore/issues/528) c-toxcore on Windows can be compiled using MSYS2 (with modern MinGW-w64)
- [#472](https://github.com/TokTok/c-toxcore/issues/472) Crash in ping_array.c:35
- [#450](https://github.com/TokTok/c-toxcore/issues/450) Run format-test earlier in the build
- [#429](https://github.com/TokTok/c-toxcore/issues/429) Cannot build on Windows using MinGW

## v0.2.3

### Merged PRs:

- [#952](https://github.com/TokTok/c-toxcore/pull/952) Release v0.2.3
- [#951](https://github.com/TokTok/c-toxcore/pull/951) Only run astyle if the astyle binary exists.
- [#950](https://github.com/TokTok/c-toxcore/pull/950) Remove utils.c and utils.h from toxencryptsave build.
- [#949](https://github.com/TokTok/c-toxcore/pull/949) Fixes to the imported sodium sources to compile without warnings.
- [#948](https://github.com/TokTok/c-toxcore/pull/948) Add a MAX_HOSTNAME_LENGTH constant.
- [#947](https://github.com/TokTok/c-toxcore/pull/947) Remove the format test.
- [#937](https://github.com/TokTok/c-toxcore/pull/937) Add new Circle CI configuration.
- [#935](https://github.com/TokTok/c-toxcore/pull/935) Add a test for double conference invite.
- [#933](https://github.com/TokTok/c-toxcore/pull/933) Add Logger to various net_crypto functions, and add `const` to Logger where possible.
- [#931](https://github.com/TokTok/c-toxcore/pull/931) Avoid conditional-uninitialised warning for tcp test.
- [#930](https://github.com/TokTok/c-toxcore/pull/930) Disable UDP when proxy is enabled.
- [#928](https://github.com/TokTok/c-toxcore/pull/928) Use clang-format for C++ code.
- [#927](https://github.com/TokTok/c-toxcore/pull/927) Add assertions to bootstrap tests for correct connection type.
- [#926](https://github.com/TokTok/c-toxcore/pull/926) Make NULL options behave the same as default options.
- [#925](https://github.com/TokTok/c-toxcore/pull/925) Add tests for what happens when passing an invalid proxy host.
- [#924](https://github.com/TokTok/c-toxcore/pull/924) Make the net_crypto connection state an enum.
- [#922](https://github.com/TokTok/c-toxcore/pull/922) Clarify/Improve test_some test
- [#921](https://github.com/TokTok/c-toxcore/pull/921) Beginnings of a TCP_test.c overhaul
- [#920](https://github.com/TokTok/c-toxcore/pull/920) Add test for creating multiple conferences in one tox.
- [#918](https://github.com/TokTok/c-toxcore/pull/918) Merge irungentoo/master into toktok
- [#917](https://github.com/TokTok/c-toxcore/pull/917) Add random testing program.
- [#916](https://github.com/TokTok/c-toxcore/pull/916) Fix linking with address sanitizer.
- [#915](https://github.com/TokTok/c-toxcore/pull/915) Remove resource_leak_test.
- [#914](https://github.com/TokTok/c-toxcore/pull/914) Make dht_test more stable.
- [#913](https://github.com/TokTok/c-toxcore/pull/913) Minor cleanup: return early on error condition.
- [#906](https://github.com/TokTok/c-toxcore/pull/906) Sort bazel build file according to buildifier standard.
- [#905](https://github.com/TokTok/c-toxcore/pull/905) In DEBUG mode, make toxcore crash on signed integer overflow.
- [#902](https://github.com/TokTok/c-toxcore/pull/902) Log only the filename, not the full path in LOGGER.
- [#899](https://github.com/TokTok/c-toxcore/pull/899) Fix macOS macro because of GNU Mach
- [#898](https://github.com/TokTok/c-toxcore/pull/898) Fix enumeration of Crypto_Connection instances
- [#897](https://github.com/TokTok/c-toxcore/pull/897) Fix ipport_isset: port 0 is not a valid port.
- [#894](https://github.com/TokTok/c-toxcore/pull/894) Fix logging related crash in bootstrap node
- [#893](https://github.com/TokTok/c-toxcore/pull/893) Fix bootstrap crashes, still
- [#892](https://github.com/TokTok/c-toxcore/pull/892) Add empty logger to DHT bootstrap daemons.
- [#887](https://github.com/TokTok/c-toxcore/pull/887) Fix FreeBSD build on Travis
- [#884](https://github.com/TokTok/c-toxcore/pull/884) Fix the often call of event tox_friend_connection_status
- [#883](https://github.com/TokTok/c-toxcore/pull/883) Make toxcore compile on BSD
- [#878](https://github.com/TokTok/c-toxcore/pull/878) fix DHT_bootstrap key loading
- [#877](https://github.com/TokTok/c-toxcore/pull/877) Add minitox to under "Other resources" section in the README
- [#875](https://github.com/TokTok/c-toxcore/pull/875) Make bootstrap daemon use toxcore's version
- [#867](https://github.com/TokTok/c-toxcore/pull/867) Improve network error reporting on Windows
- [#841](https://github.com/TokTok/c-toxcore/pull/841) Only check full rtp offset if RTP_LARGE_FRAME is set
- [#823](https://github.com/TokTok/c-toxcore/pull/823) Finish @Diadlo's network Family abstraction.
- [#822](https://github.com/TokTok/c-toxcore/pull/822) Move system header includes from network.h to network.c

### Closed issues:

- [#900](https://github.com/TokTok/c-toxcore/issues/900) Log messages include the full build path
- [#881](https://github.com/TokTok/c-toxcore/issues/881) Toxcore does not build with cmake on OpenBSD.
- [#879](https://github.com/TokTok/c-toxcore/issues/879) DHT_bootstrap asserts due to no default logger
- [#868](https://github.com/TokTok/c-toxcore/issues/868) A tox_friend_connection_status event often occurs

## v0.2.2

### Merged PRs:

- [#872](https://github.com/TokTok/c-toxcore/pull/872) Restrict packet kinds that can be sent through onion path.
- [#864](https://github.com/TokTok/c-toxcore/pull/864) CMake warn if libconfig not found
- [#863](https://github.com/TokTok/c-toxcore/pull/863) Remove broken and unmaintained scripts.
- [#862](https://github.com/TokTok/c-toxcore/pull/862) Release v0.2.2
- [#859](https://github.com/TokTok/c-toxcore/pull/859) Add clarifying comment to cryptpacket_received function.
- [#857](https://github.com/TokTok/c-toxcore/pull/857) Avoid the use of rand() in tests.
- [#852](https://github.com/TokTok/c-toxcore/pull/852) bugfix build error on MacOS
- [#846](https://github.com/TokTok/c-toxcore/pull/846) Disallow stderr logger by default.
- [#845](https://github.com/TokTok/c-toxcore/pull/845) Fix coveralls reporting.
- [#844](https://github.com/TokTok/c-toxcore/pull/844) Add COVERAGE cmake flag for clang.
- [#825](https://github.com/TokTok/c-toxcore/pull/825) Add default stderr logger for logging to nullptr.
- [#824](https://github.com/TokTok/c-toxcore/pull/824) Simplify sendpacket function, deduplicate some logic.
- [#809](https://github.com/TokTok/c-toxcore/pull/809) Remove the use of the 'hh' format specifier.
- [#801](https://github.com/TokTok/c-toxcore/pull/801) Add logging to the onion_test.
- [#797](https://github.com/TokTok/c-toxcore/pull/797) Move struct DHT_Friend into DHT.c.

### Closed issues:

- [#873](https://github.com/TokTok/c-toxcore/issues/873) Onion vulnerability
- [#786](https://github.com/TokTok/c-toxcore/issues/786) Make format strings msvc/mingw-happy

## v0.2.1

### Merged PRs:

- [#839](https://github.com/TokTok/c-toxcore/pull/839) Update changelog for 0.2.1
- [#837](https://github.com/TokTok/c-toxcore/pull/837) Update version to 0.2.1.
- [#833](https://github.com/TokTok/c-toxcore/pull/833) Add missing tox_nospam_size() function
- [#832](https://github.com/TokTok/c-toxcore/pull/832) Don't set RTP_LARGE_FRAME on rtp audio packets
- [#831](https://github.com/TokTok/c-toxcore/pull/831) Don't throw away rtp packets from old Toxcore
- [#828](https://github.com/TokTok/c-toxcore/pull/828) Make file transfers 50% faster.

## v0.2.0

### Merged PRs:

- [#821](https://github.com/TokTok/c-toxcore/pull/821) Remove deprecated conference namelist change callback.
- [#820](https://github.com/TokTok/c-toxcore/pull/820) Fix auto_tests to stop using the deprecated conference API.
- [#819](https://github.com/TokTok/c-toxcore/pull/819) Change default username to empty string
- [#818](https://github.com/TokTok/c-toxcore/pull/818) Change README to talk about cmake instead of autoreconf.
- [#817](https://github.com/TokTok/c-toxcore/pull/817) Fix warning on Mac OS X and FreeBSD.
- [#815](https://github.com/TokTok/c-toxcore/pull/815) Some minor cleanups suggested by cppcheck.
- [#814](https://github.com/TokTok/c-toxcore/pull/814) Fix memory leak of Logger instance on error paths.
- [#813](https://github.com/TokTok/c-toxcore/pull/813) Minor cleanups: dead stores and avoiding complex macros.
- [#811](https://github.com/TokTok/c-toxcore/pull/811) Update changelog for 0.2.0
- [#808](https://github.com/TokTok/c-toxcore/pull/808) Fix a bunch of compiler warnings and remove suppressions.
- [#807](https://github.com/TokTok/c-toxcore/pull/807) Link all tests to the android cpufeatures library if available.
- [#806](https://github.com/TokTok/c-toxcore/pull/806) Fix toxcore.pc generation.
- [#805](https://github.com/TokTok/c-toxcore/pull/805) Add an option that allows us to specify that we require toxav.
- [#804](https://github.com/TokTok/c-toxcore/pull/804) Fix OSX tests: find(1) doesn't work like on Linux.
- [#803](https://github.com/TokTok/c-toxcore/pull/803) Fix the windows build: pthread needs to be linked after vpx.
- [#800](https://github.com/TokTok/c-toxcore/pull/800) Make group number in the toxav public API uint32_t
- [#799](https://github.com/TokTok/c-toxcore/pull/799) Implement the "persistent conference" callback changes as new functions.
- [#798](https://github.com/TokTok/c-toxcore/pull/798) Add deprecation notices to functions that will go away in v0.3.0.
- [#796](https://github.com/TokTok/c-toxcore/pull/796) Make some sizeof tests linux-only.
- [#794](https://github.com/TokTok/c-toxcore/pull/794) Remove apidsl from the build.
- [#793](https://github.com/TokTok/c-toxcore/pull/793) Add a bazel test that ensures all our projects are GPL-3.0.
- [#792](https://github.com/TokTok/c-toxcore/pull/792) Increase range of ports available to Toxes during tests
- [#791](https://github.com/TokTok/c-toxcore/pull/791) Run all tests in parallel on Travis.
- [#790](https://github.com/TokTok/c-toxcore/pull/790) Disable lan discovery in most tests.
- [#789](https://github.com/TokTok/c-toxcore/pull/789) Remove tox_test from autotools build.
- [#788](https://github.com/TokTok/c-toxcore/pull/788) Don't print trace level logging in tests.
- [#787](https://github.com/TokTok/c-toxcore/pull/787) Split up tox_test into multiple smaller tests
- [#784](https://github.com/TokTok/c-toxcore/pull/784) Use Wine Devel instead of Wine Staging
- [#783](https://github.com/TokTok/c-toxcore/pull/783) Send 0 as peer number in CHANGE_OCCURRED group event.
- [#782](https://github.com/TokTok/c-toxcore/pull/782) Use `const` more in C code.
- [#781](https://github.com/TokTok/c-toxcore/pull/781) Don't build all the small sub-libraries.
- [#780](https://github.com/TokTok/c-toxcore/pull/780) Get rid of the only GNU extension we used.
- [#779](https://github.com/TokTok/c-toxcore/pull/779) Remove leftover symmetric key from DHT struct.
- [#778](https://github.com/TokTok/c-toxcore/pull/778) Add static asserts for all the struct sizes in toxcore.
- [#776](https://github.com/TokTok/c-toxcore/pull/776) Optionally use newer cmake features.
- [#775](https://github.com/TokTok/c-toxcore/pull/775) Look for dependencies in third_party/
- [#774](https://github.com/TokTok/c-toxcore/pull/774) Improve gtest finding, support local checkout.
- [#773](https://github.com/TokTok/c-toxcore/pull/773) Add gtest include directory to -I flags if found.
- [#772](https://github.com/TokTok/c-toxcore/pull/772) Reject discovery packets coming from outside the "LAN".
- [#771](https://github.com/TokTok/c-toxcore/pull/771) Adopt the "change occurred" API change from isotoxin-groupchat.
- [#770](https://github.com/TokTok/c-toxcore/pull/770) Add MSVC compilation instructions
- [#767](https://github.com/TokTok/c-toxcore/pull/767) Build toxcore with libsodium.dll instead of libsodium.lib.
- [#766](https://github.com/TokTok/c-toxcore/pull/766) Remove libcheck from the dependencies.
- [#765](https://github.com/TokTok/c-toxcore/pull/765) Make outgoing Filetransfers round-robin.
- [#764](https://github.com/TokTok/c-toxcore/pull/764) Fix LAN discovery on FreeBSD.
- [#761](https://github.com/TokTok/c-toxcore/pull/761) use official debian domain
- [#760](https://github.com/TokTok/c-toxcore/pull/760) Make cmake script more forgiving.
- [#759](https://github.com/TokTok/c-toxcore/pull/759) Use more ubuntu packages; remove hstox for now.
- [#757](https://github.com/TokTok/c-toxcore/pull/757) Improve stability of crypto_memcmp test.
- [#756](https://github.com/TokTok/c-toxcore/pull/756) Format .cpp files with format-source.
- [#755](https://github.com/TokTok/c-toxcore/pull/755) Add some unit tests for util.h.
- [#754](https://github.com/TokTok/c-toxcore/pull/754) Move the tox_sync tool to the toxins repository.
- [#753](https://github.com/TokTok/c-toxcore/pull/753) Move irc_syncbot to the toxins repository.
- [#752](https://github.com/TokTok/c-toxcore/pull/752) Move tox_shell program to the toxins repository.
- [#751](https://github.com/TokTok/c-toxcore/pull/751) Use the markdown GPLv3 license in the c-toxcore repo.
- [#750](https://github.com/TokTok/c-toxcore/pull/750) Remove csrc from the RTPHeader struct.
- [#748](https://github.com/TokTok/c-toxcore/pull/748) Revert "Add correction message type"
- [#745](https://github.com/TokTok/c-toxcore/pull/745) Change the "capabilities" field to a "flags" field.
- [#742](https://github.com/TokTok/c-toxcore/pull/742) Improve conference test stability.
- [#741](https://github.com/TokTok/c-toxcore/pull/741) Add `-D__STDC_LIMIT_MACROS=1` for C++ code.
- [#739](https://github.com/TokTok/c-toxcore/pull/739) Add RTP header fields for the full frame length and offset.
- [#737](https://github.com/TokTok/c-toxcore/pull/737) Use nullptr as NULL pointer constant instead of NULL or 0.
- [#736](https://github.com/TokTok/c-toxcore/pull/736) Avoid clashes with "build" directories on case-insensitive file systems.
- [#734](https://github.com/TokTok/c-toxcore/pull/734) Make audio/video bit rates "properties"
- [#733](https://github.com/TokTok/c-toxcore/pull/733) Fix link in README.md
- [#730](https://github.com/TokTok/c-toxcore/pull/730) Fix out of bounds read in error case in messenger_test.
- [#729](https://github.com/TokTok/c-toxcore/pull/729) Remove dead return statement.
- [#728](https://github.com/TokTok/c-toxcore/pull/728) Disable the autotools build in PR builds.
- [#727](https://github.com/TokTok/c-toxcore/pull/727) Rename some rtp header struct members to be clearer.
- [#725](https://github.com/TokTok/c-toxcore/pull/725) Publish a single public BUILD target for c-toxcore.
- [#723](https://github.com/TokTok/c-toxcore/pull/723) Use <stdlib.h> for alloca on FreeBSD.
- [#722](https://github.com/TokTok/c-toxcore/pull/722) Use self-built portaudio instead of system-provided.
- [#721](https://github.com/TokTok/c-toxcore/pull/721) Manually serialise RTPHeader struct instead of memcpy.
- [#718](https://github.com/TokTok/c-toxcore/pull/718) Improve sending of large video frames in toxav.
- [#716](https://github.com/TokTok/c-toxcore/pull/716) Add comment from #629 in ring_buffer.c.
- [#714](https://github.com/TokTok/c-toxcore/pull/714) Make BUILD files more finely-grained.
- [#713](https://github.com/TokTok/c-toxcore/pull/713) Add BUILD files for all the little tools in the repo.
- [#712](https://github.com/TokTok/c-toxcore/pull/712) Fix high quality video sending (backport to 0.1.x).
- [#711](https://github.com/TokTok/c-toxcore/pull/711) Make the monolith test a C++ binary.
- [#710](https://github.com/TokTok/c-toxcore/pull/710) Don't allocate or dereference Tox_Options in tests.
- [#709](https://github.com/TokTok/c-toxcore/pull/709) Remove nTox from the repo.
- [#708](https://github.com/TokTok/c-toxcore/pull/708) Add testing/*.c (except av_test) to bazel build.
- [#707](https://github.com/TokTok/c-toxcore/pull/707) Fix log message in simple_conference_test: invite -> message.
- [#705](https://github.com/TokTok/c-toxcore/pull/705) Add correction support for conference
- [#703](https://github.com/TokTok/c-toxcore/pull/703) Add a simple conference test with 3 friends.
- [#702](https://github.com/TokTok/c-toxcore/pull/702) Update to astyle 2.04 on CircleCI to get the correct result
- [#701](https://github.com/TokTok/c-toxcore/pull/701) Add astyle to Circle CI build.
- [#700](https://github.com/TokTok/c-toxcore/pull/700) Use more descriptive names in bwcontroller.
- [#699](https://github.com/TokTok/c-toxcore/pull/699) Add some explanatory comments to the toxav audio code.
- [#698](https://github.com/TokTok/c-toxcore/pull/698) Extract named constants from magic numbers in toxav/audio.c.
- [#697](https://github.com/TokTok/c-toxcore/pull/697) Use C99 standard in bazel builds.
- [#694](https://github.com/TokTok/c-toxcore/pull/694) Add bazel build scripts for c-toxcore.
- [#693](https://github.com/TokTok/c-toxcore/pull/693) Make libcheck optional for windows builds.
- [#691](https://github.com/TokTok/c-toxcore/pull/691) Don't install packages needlessly on Travis
- [#690](https://github.com/TokTok/c-toxcore/pull/690) Run fewer Travis jobs during Pull Requests.
- [#689](https://github.com/TokTok/c-toxcore/pull/689) Make Net_Crypto a module-private type.
- [#688](https://github.com/TokTok/c-toxcore/pull/688) Make DHT a module-private type.
- [#687](https://github.com/TokTok/c-toxcore/pull/687) Use apidsl to generate LAN_discovery.h.
- [#686](https://github.com/TokTok/c-toxcore/pull/686) Remove hstox test for now.
- [#685](https://github.com/TokTok/c-toxcore/pull/685) Add message type for correction
- [#684](https://github.com/TokTok/c-toxcore/pull/684) Add random_u16 function and rename the others to match.
- [#682](https://github.com/TokTok/c-toxcore/pull/682) Use larger arrays in crypto timing tests.
- [#681](https://github.com/TokTok/c-toxcore/pull/681) Fix some memory or file descriptor leaks in test code.
- [#680](https://github.com/TokTok/c-toxcore/pull/680) Filter out annoying log statements in unit tests.
- [#679](https://github.com/TokTok/c-toxcore/pull/679) Use apidsl to generate ping.h.
- [#678](https://github.com/TokTok/c-toxcore/pull/678) Sort monolith.h according to ls(1): uppercase first.
- [#677](https://github.com/TokTok/c-toxcore/pull/677) Make pack/unpack_ip_port public DHT functions.
- [#675](https://github.com/TokTok/c-toxcore/pull/675) Make Onion_Announce a module-private type.
- [#674](https://github.com/TokTok/c-toxcore/pull/674) Make TCP_Client_Connection a module-private type.
- [#673](https://github.com/TokTok/c-toxcore/pull/673) Move TCP_Secure_Connection from .h to .c file.
- [#672](https://github.com/TokTok/c-toxcore/pull/672) Make Friend_Connections a module-private type.
- [#670](https://github.com/TokTok/c-toxcore/pull/670) Make Friend_Requests a module-private type.
- [#669](https://github.com/TokTok/c-toxcore/pull/669) Make Onion_Client a module-private type.
- [#668](https://github.com/TokTok/c-toxcore/pull/668) Make Ping_Array a module-private type.
- [#667](https://github.com/TokTok/c-toxcore/pull/667) pkg-config .pc files: added .private versions of Libs and Required
- [#666](https://github.com/TokTok/c-toxcore/pull/666) Fix some typos in code and cmake comments
- [#665](https://github.com/TokTok/c-toxcore/pull/665) Remove useless if statement
- [#662](https://github.com/TokTok/c-toxcore/pull/662) Move Networking_Core struct into the .c file.
- [#661](https://github.com/TokTok/c-toxcore/pull/661) Disable asan, since it seems to break on travis.
- [#660](https://github.com/TokTok/c-toxcore/pull/660) Increase test retries to 10 (basically infinite).
- [#659](https://github.com/TokTok/c-toxcore/pull/659) Fix formatting in some C files.
- [#658](https://github.com/TokTok/c-toxcore/pull/658) Call freeaddrinfo on error paths in net_getipport.
- [#657](https://github.com/TokTok/c-toxcore/pull/657) Zero-initialise stack-allocated objects in hstox driver.
- [#656](https://github.com/TokTok/c-toxcore/pull/656) Fix file descriptor leak in hstox test.
- [#654](https://github.com/TokTok/c-toxcore/pull/654) Bump toxcore version to 0.2.0.
- [#652](https://github.com/TokTok/c-toxcore/pull/652) Add support for building the monolith test on android.
- [#650](https://github.com/TokTok/c-toxcore/pull/650) Remove deprecated ToxDNS
- [#648](https://github.com/TokTok/c-toxcore/pull/648) Make hstox compile on FreeBSD
- [#624](https://github.com/TokTok/c-toxcore/pull/624) Update rpm spec and use variables in cmake instead of hardcoded paths
- [#616](https://github.com/TokTok/c-toxcore/pull/616) Add projects link to Readme.
- [#613](https://github.com/TokTok/c-toxcore/pull/613) Fix travis
- [#605](https://github.com/TokTok/c-toxcore/pull/605) Fix OS X Travis.
- [#598](https://github.com/TokTok/c-toxcore/pull/598) Fix typos in docs
- [#578](https://github.com/TokTok/c-toxcore/pull/578) Split toxav_bit_rate_set() into two functions to hold the maximum bitrates libvpx supports
- [#477](https://github.com/TokTok/c-toxcore/pull/477) Update install instructions to use CMake
- [#465](https://github.com/TokTok/c-toxcore/pull/465) Add Alpine linux Dockerfile in addition to the existing Debian one
- [#442](https://github.com/TokTok/c-toxcore/pull/442) Generate only one large library "libtoxcore".
- [#334](https://github.com/TokTok/c-toxcore/pull/334) Change toxencryptsave API to never overwrite pass keys.

### Closed issues:

- [#810](https://github.com/TokTok/c-toxcore/issues/810) Release 0.2.0
- [#704](https://github.com/TokTok/c-toxcore/issues/704) Add CORRECTION support to group chats
- [#620](https://github.com/TokTok/c-toxcore/issues/620) Video bug: large video frames are not sent correctly
- [#606](https://github.com/TokTok/c-toxcore/issues/606) groupId is int whereas friendId is uint32_t, reason?
- [#599](https://github.com/TokTok/c-toxcore/issues/599) Error when linking against libtoxcore: undefined reference to symbol 'crypto_hash_sha256'
- [#572](https://github.com/TokTok/c-toxcore/issues/572) int32_t may be not large enough as a argument for video_bit_rate of vp8/9 codec
- [#566](https://github.com/TokTok/c-toxcore/issues/566) LAYER #: modules for static linking - build issue
- [#383](https://github.com/TokTok/c-toxcore/issues/383) TODO: add cmake instructions in README.md
- [#42](https://github.com/TokTok/c-toxcore/issues/42) Remove ToxDNS and related stuff from toxcore

## v0.1.11

### Merged PRs:

- [#643](https://github.com/TokTok/c-toxcore/pull/643) Add .editorconfig
- [#638](https://github.com/TokTok/c-toxcore/pull/638) Release v0.1.11
- [#637](https://github.com/TokTok/c-toxcore/pull/637) Update tox-bootstrapd Dockerfile
- [#635](https://github.com/TokTok/c-toxcore/pull/635) Separate FreeBSD Travis build in 2 stages
- [#632](https://github.com/TokTok/c-toxcore/pull/632) Lift libconfig to v1.7.1
- [#631](https://github.com/TokTok/c-toxcore/pull/631) Add aspcud for Opam
- [#630](https://github.com/TokTok/c-toxcore/pull/630) Fix for Travis fail on addr_resolve testing
- [#623](https://github.com/TokTok/c-toxcore/pull/623) Split video payload into multiple RTP messages when too big to fit into one
- [#615](https://github.com/TokTok/c-toxcore/pull/615) forget DHT pubkey of offline friend after DHT timeout
- [#611](https://github.com/TokTok/c-toxcore/pull/611) Fix typo
- [#607](https://github.com/TokTok/c-toxcore/pull/607) set onion pingid timeout to announce timeout (300s)
- [#592](https://github.com/TokTok/c-toxcore/pull/592) Adjust docs of few toxencrypt function to the code
- [#587](https://github.com/TokTok/c-toxcore/pull/587) Fix tox test
- [#586](https://github.com/TokTok/c-toxcore/pull/586) Improve LAN discovery
- [#576](https://github.com/TokTok/c-toxcore/pull/576) Replace include(CTest) on enable_testing()
- [#574](https://github.com/TokTok/c-toxcore/pull/574) Reset hole-punching parameters after not punching for a while
- [#571](https://github.com/TokTok/c-toxcore/pull/571) Configure needs to find libsodium headers.
- [#515](https://github.com/TokTok/c-toxcore/pull/515) Network cleanup: reduce dependency on system-defined constants
- [#505](https://github.com/TokTok/c-toxcore/pull/505) Add FreeBSD Travis
- [#500](https://github.com/TokTok/c-toxcore/pull/500) Fixed the bug when receipts for messages sent from the receipt callback never arrived.

### Closed issues:

- [#493](https://github.com/TokTok/c-toxcore/issues/493) Receipts for messages sent from the receipt callback never arrive
- [#240](https://github.com/TokTok/c-toxcore/issues/240) Tox doesn't reconnect after internet connection interruption
- [#237](https://github.com/TokTok/c-toxcore/issues/237) Contacts are shown offline when they are online

## v0.1.10

### Merged PRs:

- [#575](https://github.com/TokTok/c-toxcore/pull/575) Release v0.1.10
- [#564](https://github.com/TokTok/c-toxcore/pull/564) Fix Windows build
- [#542](https://github.com/TokTok/c-toxcore/pull/542) Save bandwidth by moderating onion pinging

## v0.1.9

### Merged PRs:

- [#563](https://github.com/TokTok/c-toxcore/pull/563) Release v0.1.9
- [#561](https://github.com/TokTok/c-toxcore/pull/561) Remove unused variable
- [#560](https://github.com/TokTok/c-toxcore/pull/560) Fix non-portable zeroing out of doubles
- [#559](https://github.com/TokTok/c-toxcore/pull/559) Fix theoretical memory leaks
- [#557](https://github.com/TokTok/c-toxcore/pull/557) Document inverted mutex lock/unlock.
- [#556](https://github.com/TokTok/c-toxcore/pull/556) Build tests on appveyor, the MSVC build, but don't run them yet.
- [#555](https://github.com/TokTok/c-toxcore/pull/555) Fold hstox tests into the general linux test.
- [#554](https://github.com/TokTok/c-toxcore/pull/554) Add a monolith_test that includes all toxcore sources.
- [#553](https://github.com/TokTok/c-toxcore/pull/553) Factor out strict_abi cmake code into a separate module.
- [#552](https://github.com/TokTok/c-toxcore/pull/552) Fix formatting and spelling in version-sync script.
- [#551](https://github.com/TokTok/c-toxcore/pull/551) Forbid undefined symbols in shared libraries.
- [#546](https://github.com/TokTok/c-toxcore/pull/546) Make variable names in file saving test less cryptic
- [#539](https://github.com/TokTok/c-toxcore/pull/539) Make OSX test failures fail the Travis CI build.
- [#537](https://github.com/TokTok/c-toxcore/pull/537) Fix TokTok/c-toxcore#535
- [#534](https://github.com/TokTok/c-toxcore/pull/534) Fix markdown formatting
- [#530](https://github.com/TokTok/c-toxcore/pull/530) Implement missing TES constant functions.
- [#511](https://github.com/TokTok/c-toxcore/pull/511) Save bandwidth by avoiding superfluous Nodes Requests to peers already on the Close List
- [#506](https://github.com/TokTok/c-toxcore/pull/506) Add test case for title change
- [#498](https://github.com/TokTok/c-toxcore/pull/498) DHT refactoring
- [#487](https://github.com/TokTok/c-toxcore/pull/487) Split daemon's logging backends in separate modules
- [#468](https://github.com/TokTok/c-toxcore/pull/468) Test for memberlist not changing after changing own name
- [#449](https://github.com/TokTok/c-toxcore/pull/449) Use new encoding of `Maybe` in msgpack results.

### Closed issues:

- [#482](https://github.com/TokTok/c-toxcore/issues/482) CMake can't detect and compile ToxAV on OSX

## v0.1.8

### Merged PRs:

- [#538](https://github.com/TokTok/c-toxcore/pull/538) Reverting tox_loop PR changes
- [#536](https://github.com/TokTok/c-toxcore/pull/536) Release v0.1.8
- [#526](https://github.com/TokTok/c-toxcore/pull/526) Add TOX_NOSPAM_SIZE to the public API.
- [#525](https://github.com/TokTok/c-toxcore/pull/525) Retry autotools tests the same way as cmake tests.
- [#524](https://github.com/TokTok/c-toxcore/pull/524) Reduce ctest timeout to 2 minutes from 5 minutes.
- [#512](https://github.com/TokTok/c-toxcore/pull/512) Add test for DHT pack_nodes and unpack_nodes
- [#504](https://github.com/TokTok/c-toxcore/pull/504) CMake: install bootstrapd if it is built
- [#488](https://github.com/TokTok/c-toxcore/pull/488) Save compiled Android artifacts after CircleCI builds.
- [#473](https://github.com/TokTok/c-toxcore/pull/473) Added missing includes: <netinet/in.h> and <sys/socket.h>
- [#335](https://github.com/TokTok/c-toxcore/pull/335) Implement tox_loop

### Closed issues:

- [#535](https://github.com/TokTok/c-toxcore/issues/535) OS X tests failing
- [#503](https://github.com/TokTok/c-toxcore/issues/503) Undefined functions: tox_pass_salt_length, tox_pass_key_length, tox_pass_encryption_extra_length
- [#456](https://github.com/TokTok/c-toxcore/issues/456) Tox.h doesn't expose the size of the nospam.
- [#411](https://github.com/TokTok/c-toxcore/issues/411) Reduce CTest timeout to 2 minutes

## v0.1.7

### Merged PRs:

- [#523](https://github.com/TokTok/c-toxcore/pull/523) Release v0.1.7
- [#521](https://github.com/TokTok/c-toxcore/pull/521) Fix appveyor script: install curl from chocolatey.
- [#510](https://github.com/TokTok/c-toxcore/pull/510) Fix list malloc(0) bug
- [#509](https://github.com/TokTok/c-toxcore/pull/509) Fix network malloc(0) bug
- [#497](https://github.com/TokTok/c-toxcore/pull/497) Fix network
- [#496](https://github.com/TokTok/c-toxcore/pull/496) Fix Travis always succeeding despite tests failing
- [#491](https://github.com/TokTok/c-toxcore/pull/491) Add crypto_memzero for temp buffer
- [#490](https://github.com/TokTok/c-toxcore/pull/490) Move c_sleep to helpers.h and misc_tools.h
- [#486](https://github.com/TokTok/c-toxcore/pull/486) Remove empty line in Messenger.c
- [#483](https://github.com/TokTok/c-toxcore/pull/483) Make BUILD_TOXAV an option and fail if dependencies are missing
- [#481](https://github.com/TokTok/c-toxcore/pull/481) Remove dependency on strings.h
- [#480](https://github.com/TokTok/c-toxcore/pull/480) Use VLA macro
- [#479](https://github.com/TokTok/c-toxcore/pull/479) Fix pthreads in AppVeyor build
- [#471](https://github.com/TokTok/c-toxcore/pull/471) Remove statics used in onion comparison functions.
- [#461](https://github.com/TokTok/c-toxcore/pull/461) Replace part of network functions on platform-independent implementation
- [#452](https://github.com/TokTok/c-toxcore/pull/452) Add VLA compatibility macro for C89-ish compilers.

### Closed issues:

- [#495](https://github.com/TokTok/c-toxcore/issues/495) Fix heap buffer overflow introduced by #461
- [#494](https://github.com/TokTok/c-toxcore/issues/494) Format networking code introduced by #461
- [#474](https://github.com/TokTok/c-toxcore/issues/474) TOX_VERSION_PATCH isn't in sync with the version

## v0.1.6

### Merged PRs:

- [#460](https://github.com/TokTok/c-toxcore/pull/460) Release v0.1.6.
- [#459](https://github.com/TokTok/c-toxcore/pull/459) Add Android build to CI.
- [#454](https://github.com/TokTok/c-toxcore/pull/454) Add appveyor build for native windows tests.
- [#448](https://github.com/TokTok/c-toxcore/pull/448) Only retry failed tests on Circle CI instead of all.
- [#434](https://github.com/TokTok/c-toxcore/pull/434) Replace redundant packet type check in handler with assert.
- [#432](https://github.com/TokTok/c-toxcore/pull/432) Remove some static variables
- [#385](https://github.com/TokTok/c-toxcore/pull/385) Add platform-independent Socket and IP implementation

### Closed issues:

- [#457](https://github.com/TokTok/c-toxcore/issues/457) EPOLLRDHUP not defined in android ndk on lower API that 21
- [#415](https://github.com/TokTok/c-toxcore/issues/415) Set up a native windows build on appveyor

## v0.1.5

### Merged PRs:

- [#447](https://github.com/TokTok/c-toxcore/pull/447) Release v0.1.5.
- [#446](https://github.com/TokTok/c-toxcore/pull/446) Limit number of retries to 3.
- [#445](https://github.com/TokTok/c-toxcore/pull/445) Make Travis tests slightly more robust by re-running them.
- [#443](https://github.com/TokTok/c-toxcore/pull/443) Make building `DHT_bootstrap` in cmake optional.
- [#433](https://github.com/TokTok/c-toxcore/pull/433) Add tutorial and "danger: experimental" banner to README.
- [#431](https://github.com/TokTok/c-toxcore/pull/431) Update license headers and remove redundant file name comment.
- [#424](https://github.com/TokTok/c-toxcore/pull/424) Fixed the FreeBSD build failure due to the undefined MSG_NOSIGNAL.
- [#420](https://github.com/TokTok/c-toxcore/pull/420) Setup autotools to read .so version info from a separate file
- [#418](https://github.com/TokTok/c-toxcore/pull/418) Clarify how the autotools build is done on Travis.
- [#414](https://github.com/TokTok/c-toxcore/pull/414) Explicitly check if compiler supports C99

### Closed issues:

- [#413](https://github.com/TokTok/c-toxcore/issues/413) Support C compilation with `-std=c99` in autotools

## v0.1.4

### Merged PRs:

- [#422](https://github.com/TokTok/c-toxcore/pull/422) Release v0.1.4.
- [#410](https://github.com/TokTok/c-toxcore/pull/410) Fix NaCl build: tar was called incorrectly.
- [#409](https://github.com/TokTok/c-toxcore/pull/409) Clarify that the pass key `new` function can fail.
- [#407](https://github.com/TokTok/c-toxcore/pull/407) Don't use `git.depth=1` anymore.
- [#404](https://github.com/TokTok/c-toxcore/pull/404) Issue 404: semicolon not found
- [#403](https://github.com/TokTok/c-toxcore/pull/403) Warn on -pedantic, don't error yet.
- [#401](https://github.com/TokTok/c-toxcore/pull/401) Add logging callback to messenger_test.
- [#400](https://github.com/TokTok/c-toxcore/pull/400) Run windows tests but ignore their failures.
- [#398](https://github.com/TokTok/c-toxcore/pull/398) Portability Fixes
- [#397](https://github.com/TokTok/c-toxcore/pull/397) Replace make_quick_sort with qsort
- [#396](https://github.com/TokTok/c-toxcore/pull/396) Add an OSX build that doesn't run tests.
- [#394](https://github.com/TokTok/c-toxcore/pull/394) CMake: Add soversion to library files to generate proper symlinks
- [#393](https://github.com/TokTok/c-toxcore/pull/393) Set up autotools build to build against vanilla NaCl.
- [#392](https://github.com/TokTok/c-toxcore/pull/392) Check that TCP connections aren't dropped in callbacks.
- [#391](https://github.com/TokTok/c-toxcore/pull/391) Minor simplification in `file_seek` code.
- [#390](https://github.com/TokTok/c-toxcore/pull/390) Always kill invalid file transfers when receiving file controls.
- [#388](https://github.com/TokTok/c-toxcore/pull/388) Fix logging condition for IPv6 client timestamp updates.
- [#387](https://github.com/TokTok/c-toxcore/pull/387) Eliminate dead return statement.
- [#386](https://github.com/TokTok/c-toxcore/pull/386) Avoid accessing uninitialised memory in `net_crypto`.
- [#381](https://github.com/TokTok/c-toxcore/pull/381) Remove `TOX_DEBUG` and have asserts always enabled.

### Closed issues:

- [#378](https://github.com/TokTok/c-toxcore/issues/378) Replace all uses of `make_quick_sort` with `qsort`
- [#364](https://github.com/TokTok/c-toxcore/issues/364) Delete misc_tools.h after replacing its use by qsort.
- [#363](https://github.com/TokTok/c-toxcore/issues/363) Test against NaCl in addition to libsodium on Travis.

## v0.1.3

### Merged PRs:

- [#395](https://github.com/TokTok/c-toxcore/pull/395) Revert "Portability fixes"
- [#380](https://github.com/TokTok/c-toxcore/pull/380) Test a few cmake option combinations before the build.
- [#377](https://github.com/TokTok/c-toxcore/pull/377) Fix SSL verification in coveralls.
- [#376](https://github.com/TokTok/c-toxcore/pull/376) Bring back autotools instructions
- [#373](https://github.com/TokTok/c-toxcore/pull/373) Only fetch 1 revision from git during Travis builds.
- [#369](https://github.com/TokTok/c-toxcore/pull/369) Integrate with CircleCI to build artifacts in the future
- [#366](https://github.com/TokTok/c-toxcore/pull/366) Release v0.1.3.
- [#362](https://github.com/TokTok/c-toxcore/pull/362) Remove .cabal-sandbox option from tox-spectest find line.
- [#361](https://github.com/TokTok/c-toxcore/pull/361) Simplify integration as a third-party lib in cmake projects
- [#354](https://github.com/TokTok/c-toxcore/pull/354) Add secure memcmp and memzero implementation.
- [#324](https://github.com/TokTok/c-toxcore/pull/324) Do not compile and install DHT_bootstrap if it was disabled in configure
- [#297](https://github.com/TokTok/c-toxcore/pull/297) Portability fixes

### Closed issues:

- [#347](https://github.com/TokTok/c-toxcore/issues/347) Implement our own secure `memcmp` and `memzero` if libsodium isn't available
- [#319](https://github.com/TokTok/c-toxcore/issues/319) toxcore installs `DHT_bootstrap` even though `--disable-daemon` is passed to `./configure`

## v0.1.2

### Merged PRs:

- [#355](https://github.com/TokTok/c-toxcore/pull/355) Release v0.1.2
- [#353](https://github.com/TokTok/c-toxcore/pull/353) Fix toxav use after free caused by premature MSI destruction
- [#346](https://github.com/TokTok/c-toxcore/pull/346) Avoid array out of bounds read in friend saving.
- [#344](https://github.com/TokTok/c-toxcore/pull/344) Remove unused get/set salt/key functions from toxencryptsave.
- [#343](https://github.com/TokTok/c-toxcore/pull/343) Wrap all sodium/nacl functions in crypto_core.c.
- [#341](https://github.com/TokTok/c-toxcore/pull/341) Add test to check if tox_new/tox_kill leaks.
- [#336](https://github.com/TokTok/c-toxcore/pull/336) Correct TES docs to reflect how many bytes functions actually require.
- [#333](https://github.com/TokTok/c-toxcore/pull/333) Use `tox_options_set_*` instead of direct member access.

### Closed issues:

- [#345](https://github.com/TokTok/c-toxcore/issues/345) Array out of bounds read in "save" function
- [#342](https://github.com/TokTok/c-toxcore/issues/342) Wrap all libsodium functions we use in toxcore in `crypto_core`.
- [#278](https://github.com/TokTok/c-toxcore/issues/278) ToxAV use-after-free bug

## v0.1.1

### Merged PRs:

- [#337](https://github.com/TokTok/c-toxcore/pull/337) Release v0.1.1
- [#332](https://github.com/TokTok/c-toxcore/pull/332) Add test for encrypted savedata.
- [#330](https://github.com/TokTok/c-toxcore/pull/330) Strengthen the note about ABI compatibility in tox.h.
- [#328](https://github.com/TokTok/c-toxcore/pull/328) Drop the broken `TOX_VERSION_REQUIRE` macro.
- [#326](https://github.com/TokTok/c-toxcore/pull/326) Fix unresolved reference in toxencryptsave API docs.
- [#309](https://github.com/TokTok/c-toxcore/pull/309) Fixed attempt to join detached threads (fixes toxav test crash)
- [#306](https://github.com/TokTok/c-toxcore/pull/306) Add option to disable local peer discovery

### Closed issues:

- [#327](https://github.com/TokTok/c-toxcore/issues/327) The `TOX_VERSION_REQUIRE` macro is broken.
- [#221](https://github.com/TokTok/c-toxcore/issues/221) Option to disable local peer detection

## v0.1.0

### Merged PRs:

- [#325](https://github.com/TokTok/c-toxcore/pull/325) Fix Libs line in toxcore.pc pkg-config file.
- [#322](https://github.com/TokTok/c-toxcore/pull/322) Add compatibility pkg-config modules: libtoxcore, libtoxav.
- [#318](https://github.com/TokTok/c-toxcore/pull/318) Fix `--enable-logging` flag in autotools configure script.
- [#316](https://github.com/TokTok/c-toxcore/pull/316) Release 0.1.0.
- [#315](https://github.com/TokTok/c-toxcore/pull/315) Fix version compatibility test.
- [#314](https://github.com/TokTok/c-toxcore/pull/314) Fix off by one error in saving our own status message.
- [#313](https://github.com/TokTok/c-toxcore/pull/313) Fix padding being in the wrong place in `SAVED_FRIEND` struct
- [#312](https://github.com/TokTok/c-toxcore/pull/312) Conditionally enable non-portable assert on LP64.
- [#310](https://github.com/TokTok/c-toxcore/pull/310) Add apidsl file for toxencryptsave.
- [#307](https://github.com/TokTok/c-toxcore/pull/307) Clarify toxencryptsave documentation regarding buffer sizes
- [#305](https://github.com/TokTok/c-toxcore/pull/305) Fix static builds
- [#303](https://github.com/TokTok/c-toxcore/pull/303) Don't build nTox by default.
- [#301](https://github.com/TokTok/c-toxcore/pull/301) Renamed messenger functions, prepend `m_`.
- [#299](https://github.com/TokTok/c-toxcore/pull/299) net_crypto give handle_data_packet_helper a better name
- [#294](https://github.com/TokTok/c-toxcore/pull/294) Don't error on warnings by default

### Closed issues:

- [#317](https://github.com/TokTok/c-toxcore/issues/317) toxcore fails to build with autotools and debugging level enabled
- [#311](https://github.com/TokTok/c-toxcore/issues/311) Incorrect padding
- [#308](https://github.com/TokTok/c-toxcore/issues/308) Review TES and port it to APIDSL
- [#293](https://github.com/TokTok/c-toxcore/issues/293) error building on ubuntu 14.04
- [#292](https://github.com/TokTok/c-toxcore/issues/292) Don't build nTox by default with CMake
- [#290](https://github.com/TokTok/c-toxcore/issues/290) User Feed
- [#266](https://github.com/TokTok/c-toxcore/issues/266) Support all levels listed in TOX_DHT_NAT_LEVEL
- [#216](https://github.com/TokTok/c-toxcore/issues/216) When v0.1 release?

## v0.0.5

### Merged PRs:

- [#289](https://github.com/TokTok/c-toxcore/pull/289) Version Patch v0.0.4 => v0.0.5
- [#287](https://github.com/TokTok/c-toxcore/pull/287) Add CMake knobs to suppress building tests
- [#286](https://github.com/TokTok/c-toxcore/pull/286) Support float32 and float64 in msgpack type printer.
- [#285](https://github.com/TokTok/c-toxcore/pull/285) Mark `Tox_Options` struct as deprecated.
- [#284](https://github.com/TokTok/c-toxcore/pull/284) Add NONE enumerator to bit mask.
- [#281](https://github.com/TokTok/c-toxcore/pull/281) Made save format platform-independent
- [#277](https://github.com/TokTok/c-toxcore/pull/277) Fix a memory leak in hstox interface
- [#276](https://github.com/TokTok/c-toxcore/pull/276) Fix NULL pointer dereference in log calls
- [#275](https://github.com/TokTok/c-toxcore/pull/275) Fix a memory leak in GroupAV
- [#274](https://github.com/TokTok/c-toxcore/pull/274) Options in `new_messenger()` must never be null.
- [#271](https://github.com/TokTok/c-toxcore/pull/271) Convert to and from network byte order in set/get nospam.
- [#262](https://github.com/TokTok/c-toxcore/pull/262) Add ability to disable UDP hole punching

### Closed issues:

- [#254](https://github.com/TokTok/c-toxcore/issues/254) Add option to disable UDP hole punching
- [#215](https://github.com/TokTok/c-toxcore/issues/215) The current tox save format is non-portable
- [#205](https://github.com/TokTok/c-toxcore/issues/205) nospam value is reversed in array returned by `tox_self_get_address()`

## v0.0.4

### Merged PRs:

- [#272](https://github.com/TokTok/c-toxcore/pull/272) v0.0.4
- [#265](https://github.com/TokTok/c-toxcore/pull/265) Disable -Wunused-but-set-variable compiler warning flag.
- [#261](https://github.com/TokTok/c-toxcore/pull/261) Work around Travis issue that causes build failures.
- [#260](https://github.com/TokTok/c-toxcore/pull/260) Support arbitrary video resolutions in av_test
- [#257](https://github.com/TokTok/c-toxcore/pull/257) Add decode/encode PlainText test support.
- [#256](https://github.com/TokTok/c-toxcore/pull/256) Add spectest to the cmake test suite.
- [#255](https://github.com/TokTok/c-toxcore/pull/255) Disable some gcc-specific warnings.
- [#249](https://github.com/TokTok/c-toxcore/pull/249) Use apidsl for the crypto_core API.
- [#248](https://github.com/TokTok/c-toxcore/pull/248) Remove new_nonce function in favour of random_nonce.
- [#224](https://github.com/TokTok/c-toxcore/pull/224) Add DHT_create_packet, an abstraction for DHT RPC packets

## v0.0.3

### Merged PRs:

- [#251](https://github.com/TokTok/c-toxcore/pull/251) Rename log levels to remove the extra "LOG" prefix.
- [#250](https://github.com/TokTok/c-toxcore/pull/250) Release v0.0.3.
- [#245](https://github.com/TokTok/c-toxcore/pull/245) Change packet kind enum to use hex constants.
- [#243](https://github.com/TokTok/c-toxcore/pull/243) Enable address sanitizer on the cmake build.
- [#242](https://github.com/TokTok/c-toxcore/pull/242) Remove assoc
- [#241](https://github.com/TokTok/c-toxcore/pull/241) Move log callback to options.
- [#233](https://github.com/TokTok/c-toxcore/pull/233) Enable all possible C compiler warning flags.
- [#230](https://github.com/TokTok/c-toxcore/pull/230) Move packing and unpacking DHT request packets to DHT module.
- [#228](https://github.com/TokTok/c-toxcore/pull/228) Remove unimplemented "time delta" parameter.
- [#227](https://github.com/TokTok/c-toxcore/pull/227) Compile as C++ for windows builds.
- [#223](https://github.com/TokTok/c-toxcore/pull/223) TravisCI shorten IRC message
- [#220](https://github.com/TokTok/c-toxcore/pull/220) toxav renaming: group.{h,c} -> groupav.{h,c}
- [#218](https://github.com/TokTok/c-toxcore/pull/218) Rename some internal "group chat" thing to "conference".
- [#212](https://github.com/TokTok/c-toxcore/pull/212) Convert series of `NET_PACKET_*` defines into a typedef enum
- [#196](https://github.com/TokTok/c-toxcore/pull/196) Update readme, moved the roadmap to a higher position
- [#193](https://github.com/TokTok/c-toxcore/pull/193) Remove duplicate tests: split tests part 2.

### Closed issues:

- [#40](https://github.com/TokTok/c-toxcore/issues/40) Stateless callbacks in toxcore's public API

## v0.0.2

### Merged PRs:

- [#207](https://github.com/TokTok/c-toxcore/pull/207) docs: correct instructions for cloning & harden against repo name changes
- [#206](https://github.com/TokTok/c-toxcore/pull/206) Corrected libsodium tag
- [#204](https://github.com/TokTok/c-toxcore/pull/204) Error if format_test can't be executed.
- [#202](https://github.com/TokTok/c-toxcore/pull/202) Version Patch v0.0.2
- [#190](https://github.com/TokTok/c-toxcore/pull/190) Install libraries with RPATH.
- [#189](https://github.com/TokTok/c-toxcore/pull/189) Use `socklen_t` instead of `unsigned int` in call to `accept`.
- [#188](https://github.com/TokTok/c-toxcore/pull/188) Add option to set test timeout
- [#187](https://github.com/TokTok/c-toxcore/pull/187) Add option to build tox-bootstrapd
- [#185](https://github.com/TokTok/c-toxcore/pull/185) Import the hstox SUT interface from hstox.
- [#183](https://github.com/TokTok/c-toxcore/pull/183) Set log level for DEBUG=ON to LOG_DEBUG.
- [#182](https://github.com/TokTok/c-toxcore/pull/182) Remove return after no-return situation.
- [#181](https://github.com/TokTok/c-toxcore/pull/181) Minor documentation fixes.
- [#180](https://github.com/TokTok/c-toxcore/pull/180) Add the 'Tox' context object to the logger.
- [#179](https://github.com/TokTok/c-toxcore/pull/179) Remove the `_test` suffix in `auto_test` calls.
- [#178](https://github.com/TokTok/c-toxcore/pull/178) Rebuild apidsl'd headers in cmake.
- [#177](https://github.com/TokTok/c-toxcore/pull/177) docs(INSTALL): update compiling instructions for Linux
- [#176](https://github.com/TokTok/c-toxcore/pull/176) Merge irungentoo/toxcore into TokTok/c-toxcore.
- [#173](https://github.com/TokTok/c-toxcore/pull/173) Duplicate tox_test to 4 other files.

### Closed issues:

- [#201](https://github.com/TokTok/c-toxcore/issues/201) Logging callback was broken

## v0.0.1

### Merged PRs:

- [#174](https://github.com/TokTok/c-toxcore/pull/174) Remove redundant callback objects.
- [#171](https://github.com/TokTok/c-toxcore/pull/171) Simple Version tick to v0.0.1
- [#170](https://github.com/TokTok/c-toxcore/pull/170) C++ the second round.
- [#166](https://github.com/TokTok/c-toxcore/pull/166) Add version-sync script.
- [#164](https://github.com/TokTok/c-toxcore/pull/164) Replace `void*` with `RingBuffer*` to avoid conversions.
- [#163](https://github.com/TokTok/c-toxcore/pull/163) Move ring buffer out of toxcore/util into toxav.
- [#162](https://github.com/TokTok/c-toxcore/pull/162) Allow the OSX build to fail on travis.
- [#161](https://github.com/TokTok/c-toxcore/pull/161) Minor cleanups: unused vars, unreachable code, static globals.
- [#160](https://github.com/TokTok/c-toxcore/pull/160) Work around bug in opencv3 headers.
- [#157](https://github.com/TokTok/c-toxcore/pull/157) Make TCP_Connections module-private.
- [#156](https://github.com/TokTok/c-toxcore/pull/156) Make TCP_Server opaque.
- [#153](https://github.com/TokTok/c-toxcore/pull/153) Fix strict-ld grep expressions to include digits.
- [#151](https://github.com/TokTok/c-toxcore/pull/151) Revert #130 "Make ToxAV stateless"
- [#148](https://github.com/TokTok/c-toxcore/pull/148) Added UB comment r/t deleting a friend w/ active call
- [#146](https://github.com/TokTok/c-toxcore/pull/146) Make group callbacks stateless
- [#145](https://github.com/TokTok/c-toxcore/pull/145) Make internal chat list function take uint32_t* as well.
- [#144](https://github.com/TokTok/c-toxcore/pull/144) Only build toxav if opus and vpx are found.
- [#143](https://github.com/TokTok/c-toxcore/pull/143) Make toxcore code C++ compatible.
- [#142](https://github.com/TokTok/c-toxcore/pull/142) Fix for windows dynamic libraries.
- [#141](https://github.com/TokTok/c-toxcore/pull/141) const-correctness in windows code.
- [#140](https://github.com/TokTok/c-toxcore/pull/140) Use C99 %zu format conversion in printf for size_t.
- [#139](https://github.com/TokTok/c-toxcore/pull/139) Clean up Travis build a bit in preparation for osx/win.
- [#138](https://github.com/TokTok/c-toxcore/pull/138) Remove format-source from travis script.
- [#135](https://github.com/TokTok/c-toxcore/pull/135) Convert old groupchats to new API format
- [#134](https://github.com/TokTok/c-toxcore/pull/134) Add some astyle options to make it do more.
- [#133](https://github.com/TokTok/c-toxcore/pull/133) Ensure that all TODOs have an owner.
- [#132](https://github.com/TokTok/c-toxcore/pull/132) Remove `else` directly after `return`.
- [#130](https://github.com/TokTok/c-toxcore/pull/130) Make ToxAV stateless
- [#129](https://github.com/TokTok/c-toxcore/pull/129) Use TokTok's apidsl instead of the iphydf one.
- [#127](https://github.com/TokTok/c-toxcore/pull/127) Use "phase" script for travis build phases.
- [#126](https://github.com/TokTok/c-toxcore/pull/126) Add option to build static libraries.
- [#125](https://github.com/TokTok/c-toxcore/pull/125) Group #include directives in 3-4 groups.
- [#123](https://github.com/TokTok/c-toxcore/pull/123) Use correct logical operator for tox_test
- [#120](https://github.com/TokTok/c-toxcore/pull/120) make the majority of the callbacks stateless and add some status to a testcase
- [#118](https://github.com/TokTok/c-toxcore/pull/118) Use `const` for version numbers.
- [#117](https://github.com/TokTok/c-toxcore/pull/117) Add STRICT_ABI cmake flag to generate export lists.
- [#116](https://github.com/TokTok/c-toxcore/pull/116) Fix potential null pointer dereference.
- [#115](https://github.com/TokTok/c-toxcore/pull/115) Fix memory leak on error paths in tox_new.
- [#114](https://github.com/TokTok/c-toxcore/pull/114) Fix compilation for Windows.
- [#111](https://github.com/TokTok/c-toxcore/pull/111) Add debugging option to autotools configuration
- [#110](https://github.com/TokTok/c-toxcore/pull/110) Comment intentional switch fallthroughs
- [#109](https://github.com/TokTok/c-toxcore/pull/109) Separate ip_port packing from pack_nodes() and unpack_nodes()
- [#108](https://github.com/TokTok/c-toxcore/pull/108) Prevent `<winsock.h>` inclusion by `<windows.h>`.
- [#107](https://github.com/TokTok/c-toxcore/pull/107) Print a message about missing astyle in format-source.
- [#104](https://github.com/TokTok/c-toxcore/pull/104) Merge with irungentoo/master
- [#103](https://github.com/TokTok/c-toxcore/pull/103) Allocate `sizeof(IP_ADAPTER_INFO)` bytes instead of `sizeof(T*)`.
- [#101](https://github.com/TokTok/c-toxcore/pull/101) Add TODO for @mannol.
- [#100](https://github.com/TokTok/c-toxcore/pull/100) Remove the packet mutation in toxav's bwcontroller.
- [#99](https://github.com/TokTok/c-toxcore/pull/99) Make packet data a ptr-to-const.
- [#97](https://github.com/TokTok/c-toxcore/pull/97) Improve static and const correctness.
- [#96](https://github.com/TokTok/c-toxcore/pull/96) Improve C standard compliance.
- [#94](https://github.com/TokTok/c-toxcore/pull/94) Rearrange fields to decrease size of structure
- [#84](https://github.com/TokTok/c-toxcore/pull/84) Remove useless casts.
- [#82](https://github.com/TokTok/c-toxcore/pull/82) Add missing #include <pthread.h> to av_test.c.
- [#81](https://github.com/TokTok/c-toxcore/pull/81) Match parameter names in declarations with their definitions.
- [#80](https://github.com/TokTok/c-toxcore/pull/80) Sort #includes in all source files.
- [#79](https://github.com/TokTok/c-toxcore/pull/79) Remove redundant `return` statements.
- [#78](https://github.com/TokTok/c-toxcore/pull/78) Do not use `else` after `return`.
- [#77](https://github.com/TokTok/c-toxcore/pull/77) Add OSX and Windows build to travis config.
- [#76](https://github.com/TokTok/c-toxcore/pull/76) Remove unused and bit-rotten friends_test.
- [#75](https://github.com/TokTok/c-toxcore/pull/75) Enable build of av_test.
- [#74](https://github.com/TokTok/c-toxcore/pull/74) Add missing #includes to headers and rename tox_old to tox_group.
- [#73](https://github.com/TokTok/c-toxcore/pull/73) Add braces to all if statements.
- [#72](https://github.com/TokTok/c-toxcore/pull/72) Add getters/setters for options.
- [#70](https://github.com/TokTok/c-toxcore/pull/70) Expose constants as functions.
- [#68](https://github.com/TokTok/c-toxcore/pull/68) Add address sanitizer option to cmake file.
- [#66](https://github.com/TokTok/c-toxcore/pull/66) Fix plane size calculation in test
- [#65](https://github.com/TokTok/c-toxcore/pull/65) Avoid large stack allocations on thread stacks.
- [#64](https://github.com/TokTok/c-toxcore/pull/64) Comment out useless TODO'd if block.
- [#63](https://github.com/TokTok/c-toxcore/pull/63) Initialise the id in assoc_test.
- [#62](https://github.com/TokTok/c-toxcore/pull/62) Reduce the timeout on travis to something much more reasonable
- [#60](https://github.com/TokTok/c-toxcore/pull/60) Make friend requests stateless
- [#59](https://github.com/TokTok/c-toxcore/pull/59) Replace uint with unsigned int in assoc.c.
- [#58](https://github.com/TokTok/c-toxcore/pull/58) Make Message received receipts stateless
- [#57](https://github.com/TokTok/c-toxcore/pull/57) Make Friend User Status stateless
- [#55](https://github.com/TokTok/c-toxcore/pull/55) docs(INSTALL.md): update instructions for Gentoo
- [#54](https://github.com/TokTok/c-toxcore/pull/54) Make typing change callback stateless
- [#53](https://github.com/TokTok/c-toxcore/pull/53) Add format-source script.
- [#52](https://github.com/TokTok/c-toxcore/pull/52) Build assoc DHT code on travis.
- [#51](https://github.com/TokTok/c-toxcore/pull/51) Fix operation sequencing in TCP_test.
- [#49](https://github.com/TokTok/c-toxcore/pull/49) Apidsl test
- [#48](https://github.com/TokTok/c-toxcore/pull/48) Make friend message callback stateless
- [#46](https://github.com/TokTok/c-toxcore/pull/46) Move logging to a callback.
- [#45](https://github.com/TokTok/c-toxcore/pull/45) Stateless friend status message
- [#43](https://github.com/TokTok/c-toxcore/pull/43) Allow NULL as argument to tox_kill.
- [#41](https://github.com/TokTok/c-toxcore/pull/41) Fix warnings
- [#39](https://github.com/TokTok/c-toxcore/pull/39) Merge irungentoo/toxcore into TokTok/c-toxcore.
- [#38](https://github.com/TokTok/c-toxcore/pull/38) Try searching for libsodium with pkg-config in ./configure.
- [#37](https://github.com/TokTok/c-toxcore/pull/37) Add missing DHT_bootstrap to CMakeLists.txt.
- [#36](https://github.com/TokTok/c-toxcore/pull/36) Make tox_callback_friend_name stateless.
- [#33](https://github.com/TokTok/c-toxcore/pull/33) Update readme with tentative roadmap, removed old todo.md
- [#32](https://github.com/TokTok/c-toxcore/pull/32) Fix a bug I introduced that would make toxcore fail to initialise a second time
- [#31](https://github.com/TokTok/c-toxcore/pull/31) 7. Travis envs
- [#30](https://github.com/TokTok/c-toxcore/pull/30) 2. Hstox test
- [#29](https://github.com/TokTok/c-toxcore/pull/29) 1. Move toxcore travis build scripts out of .travis.yml.
- [#27](https://github.com/TokTok/c-toxcore/pull/27) 8. Stateless
- [#26](https://github.com/TokTok/c-toxcore/pull/26) 6. Cmake bootstrapd
- [#25](https://github.com/TokTok/c-toxcore/pull/25) 5. Coverage clang
- [#24](https://github.com/TokTok/c-toxcore/pull/24) Silence/fix some compiler warnings.
- [#23](https://github.com/TokTok/c-toxcore/pull/23) 4. Cmake
- [#20](https://github.com/TokTok/c-toxcore/pull/20) 3. Travis astyle
- [#13](https://github.com/TokTok/c-toxcore/pull/13) Enable, and report test status
- [#12](https://github.com/TokTok/c-toxcore/pull/12) Fix readme for TokTok
- [#11](https://github.com/TokTok/c-toxcore/pull/11) Documentation: SysVInit workaround for <1024 ports
- [#2](https://github.com/TokTok/c-toxcore/pull/2) Enable toxcore logging when building on Travis.
- [#1](https://github.com/TokTok/c-toxcore/pull/1) Apidsl fixes and start tracking test coverage

### Closed issues:

- [#158](https://github.com/TokTok/c-toxcore/issues/158) Error while build with OpenCV 3.1
- [#147](https://github.com/TokTok/c-toxcore/issues/147) Add comment to m_delfriend about the NULL passing to the internal conn status cb
- [#136](https://github.com/TokTok/c-toxcore/issues/136) Replace astyle by clang-format
- [#113](https://github.com/TokTok/c-toxcore/issues/113) Toxcore tests fail
- [#83](https://github.com/TokTok/c-toxcore/issues/83) Travis tests are hard to quickly parse from their output.
- [#22](https://github.com/TokTok/c-toxcore/issues/22) Make the current tests exercise both ipv4 and ipv6.
- [#9](https://github.com/TokTok/c-toxcore/issues/9) Fix the failing test
- [#8](https://github.com/TokTok/c-toxcore/issues/8) Toxcore should make more liberal use of assertions
- [#4](https://github.com/TokTok/c-toxcore/issues/4) Integrate hstox tests with toxcore Travis build
