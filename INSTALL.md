# Installation instructions

These instructions will guide you through the process of building and installing
the toxcore library and its components, as well as getting already pre-built
binaries.

## Table of contents

- [Overview](#overview)
  - [Components](#components)
    - [Main](#main)
    - [Secondary](#secondary)
- [Building](#building)
  - [Requirements](#requirements)
    - [Library dependencies](#library-dependencies)
    - [Compiler requirements](#compiler-requirements)
    - [Build system requirements](#build-system-requirements)
  - [CMake options](#cmake-options)
  - [Build process](#build-process)
    - [Unix-like](#unix-like)
    - [Windows](#windows)
      - [Building on Windows host](#building-on-windows-host)
        - [Microsoft Visual Studio's Developer Command Prompt](#microsoft-visual-studios-developer-command-prompt)
        - [MSYS/Cygwin](#msyscygwin)
      - [Cross-compiling from Linux](#cross-compiling-from-linux)
- [Pre-built binaries](#pre-built-binaries)
  - [Linux](#linux)

## Overview

### Components

#### Main

This repository, although called `toxcore`, in fact contains several libraries
besides `toxcore` which complement it, as well as several executables. However,
note that although these are separate libraries, at the moment, when building
the libraries, they are all merged into a single `toxcore` library. Here is the
full list of the main components that can be built using the CMake, their
dependencies and descriptions.

| Name             | Type       | Dependencies                       | Platform       | Description                                                                                                                |
| ---------------- | ---------- | ---------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `toxcore`        | Library    | libsodium, libm, libpthread, librt | Cross-platform | The main Tox library that provides the messenger functionality.                                                            |
| `toxav`          | Library    | libtoxcore, libopus, libvpx        | Cross-platform | Provides audio/video functionality.                                                                                        |
| `toxencryptsave` | Library    | libtoxcore, libsodium              | Cross-platform | Provides encryption of Tox profiles (savedata), as well as arbitrary data.                                                 |
| `DHT_bootstrap`  | Executable | libtoxcore                         | Cross-platform | A simple DHT bootstrap node.                                                                                               |
| `tox-bootstrapd` | Executable | libtoxcore, libconfig              | Unix-like      | Highly configurable DHT bootstrap node daemon (systemd, SysVinit, Docker).                                                 |
| `cmp`            | Library    |                                    | Cross-platform | C implementation of the MessagePack serialization format. [https://github.com/camgunz/cmp](https://github.com/camgunz/cmp) |

#### Secondary

There are some programs that are not built by default which you might find
interesting. You need to pass `-DBUILD_FUN_UTILS=ON` to cmake to build them.

##### Vanity key generators

Can be used to generate vanity Tox Ids or DHT bootstrap node public keys.

| Name             | Type       | Dependencies      | Platform       | Description                                                                                                                                                                   |
| ---------------- | ---------- | ----------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cracker`        | Executable | libsodium, OpenMP | Cross-platform | Tries to find a curve25519 key pair, hex representation of the public key of which starts with a specified byte sequence. Multi-threaded.                                     |
| `cracker_simple` | Executable | libsodium         | Cross-platform | Tries to find a curve25519 key pair, hex representation of the public key of which starts with a specified byte sequence. Single-threaded.                                    |
| `strkey`         | Executable | libsodium         | Cross-platform | Tries to find a curve25519 key pair, hex representation of the public key of which contains a specified byte sequence at a specified or any position at all. Single-threaded. |

##### Key file generators

Useful for generating Tox profiles from the output of the vanity key generators,
as well as generating random Tox profiles.

| Name                      | Type       | Dependencies          | Platform       | Description                                                                                                                                                                     |
| ------------------------- | ---------- | --------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `make-funny-savefile`     | Script     | python                | Cross-platform | Generates a Tox profile file (savedata file) with the provided key pair.                                                                                                        |
| `create_bootstrap_keys`   | Executable | libsodium             | Cross-platform | Generates a keys file for tox-bootstrapd with either the provided or a random key pair.                                                                                         |
| `create_minimal_savedata` | Executable | libsodium             | Cross-platform | Generates a minimal Tox profile file (savedata file) with either the provided or a random key pair, printing the generated Tox Id and secret & public key information.          |
| `create_savedata`         | Executable | libsodium, libtoxcore | Cross-platform | Generates a Tox profile file (savedata file) with either the provided or a random key pair using libtoxcore, printing the generated Tox Id and secret & public key information. |
| `save-generator`          | Executable | libtoxcore            | Cross-platform | Generates a Tox profile file (savedata file) with a random key pair using libtoxcore, setting the specified user name, going online and adding specified Tox Ids as friends.    |

##### Other

| Name                  | Type       | Dependencies | Platform       | Description                                                                                                                               |
| --------------------- | ---------- | ------------ | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `bootstrap_node_info` | Script     | python3      | Cross-platform | Prints version and Message Of The Day (MOTD) information of the specified DHT bootstrap node, given the node doesn't have those disabled. |
| `sign`                | Executable | libsodium    | Cross-platform | Signs a file with a ed25519 key.                                                                                                          |

## Building

### Requirements

#### Library dependencies

Library dependencies are listed in the [components](#components) table. The
dependencies need to be satisfied for the components to be built. Note that if
you don't have a dependency for some component, e.g. you don't have `libopus`
installed required for building `toxav` component, building of that component is
silently disabled.

Be advised that due to the addition of `cmp` as a submodule, you now also need
to initialize the git submodules required by toxcore. This can be done by
cloning the repo with the addition of `--recurse-submodules` or by running
`git submodule update --init` in the root directory of the repo.

#### Compiler requirements

The supported compilers are GCC, Clang and MinGW.

In theory, any compiler that fully supports C99 and accepts GCC flags should
work.

There is a partial and experimental support of Microsoft Visual C++ compiler. We
welcome any patches that help improve it.

You should have a C99 compatible compiler in order to build the main components.
The secondary components might require the compiler to support GNU extensions.

#### Build system requirements

To build the main components you need to have CMake of at least 2.8.6 version
installed. You also need to have pkg-config installed, the build system uses it
to find dependency libraries.

There is some experimental accommodation for building natively on Windows, i.e.
without having to use MSYS/Cygwin and pkg-config, but it uses exact hardcoded
paths for finding libraries and supports building only of some of toxcore
components, so your mileage might vary.

### CMake options

There are some options that are available to configure the build.

| Name                   | Description                                                                                   | Expected Value                                                            | Default Value                                     |
| ---------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------- |
| `AUTOTEST`             | Enable autotests (mainly for CI).                                                             | ON or OFF                                                                 | OFF                                               |
| `BOOTSTRAP_DAEMON`     | Enable building of tox-bootstrapd, the DHT bootstrap node daemon. For Unix-like systems only. | ON or OFF                                                                 | ON                                                |
| `BUILD_FUZZ_TESTS`     | Build fuzzing harnesses.                                                                      | ON or OFF                                                                 | OFF                                               |
| `BUILD_MISC_TESTS`     | Build additional tests.                                                                       | ON or OFF                                                                 | OFF                                               |
| `BUILD_FUN_UTILS`      | Build additional funny utilities.                                                             | ON or OFF                                                                 | OFF                                               |
| `BUILD_TOXAV`          | Whether to build the toxav library.                                                           | ON or OFF                                                                 | ON                                                |
| `CMAKE_INSTALL_PREFIX` | Path to where everything should be installed.                                                 | Directory path.                                                           | Platform-dependent. Refer to CMake documentation. |
| `CMAKE_BUILD_TYPE`     | Specifies the build type on single-configuration generators (e.g. make or ninja).             | Debug, Release, RelWithDebInfo, MinSizeRel                                | Empty string.                                     |
| `DHT_BOOTSTRAP`        | Enable building of `DHT_bootstrap`                                                            | ON or OFF                                                                 | ON                                                |
| `ENABLE_SHARED`        | Build shared (dynamic) libraries for all modules.                                             | ON or OFF                                                                 | ON                                                |
| `ENABLE_STATIC`        | Build static libraries for all modules.                                                       | ON or OFF                                                                 | ON                                                |
| `EXECUTION_TRACE`      | Print a function trace during execution (for debugging).                                      | ON or OFF                                                                 | OFF                                               |
| `FULLY_STATIC`         | Build fully static executables.                                                               | ON or OFF                                                                 | OFF                                               |
| `MIN_LOGGER_LEVEL`     | Logging level to use.                                                                         | TRACE, DEBUG, INFO, WARNING, ERROR or nothing (empty string) for default. | Empty string.                                     |
| `MSVC_STATIC_SODIUM`   | Whether to link libsodium statically for MSVC.                                                | ON or OFF                                                                 | OFF                                               |
| `MUST_BUILD_TOXAV`     | Fail the build if toxav cannot be built.                                                      | ON or OFF                                                                 | OFF                                               |
| `NON_HERMETIC_TESTS`   | Whether to build and run tests that depend on an internet connection.                         | ON or OFF                                                                 | OFF                                               |
| `STRICT_ABI`           | Enforce strict ABI export in dynamic libraries.                                               | ON or OFF                                                                 | OFF                                               |
| `TEST_TIMEOUT_SECONDS` | Limit runtime of each test to the number of seconds specified.                                | Positive number or nothing (empty string).                                | Empty string.                                     |
| `USE_IPV6`             | Use IPv6 in tests.                                                                            | ON or OFF                                                                 | ON                                                |

You can get this list of option using the following commands

```sh
grep "option(" CMakeLists.txt cmake/*
grep "set(.* CACHE" CMakeLists.txt cmake/*
```

Note that some options might be considered only if other options are enabled.

Example of calling cmake with options

```sh
cmake \
  -D ENABLE_STATIC=OFF \
  -D ENABLE_SHARED=ON \
  -D CMAKE_INSTALL_PREFIX="${PWD}/prefix" \
  -D CMAKE_BUILD_TYPE=Release \
  -D TEST_TIMEOUT_SECONDS=120 \
  ..
```

### Building tests

In addition to the integration tests ("autotests") and miscellaneous tests
enabled by cmake variables described above, there are unit tests which will be
built if the source distribution of gtest (the Google Unit Test framework) is
found by cmake in `c-toxcore/third_party`. This can be achieved by running 'git
clone https://github.com/google/googletest` from that directory.

### Build process

#### Unix-like

Assuming all the [requirements](#requirements) are met, just run

```sh
mkdir _build
cd _build
cmake ..
make
make install
```

#### Windows

##### Building on Windows host

###### Microsoft Visual Studio's Developer Command Prompt

In addition to meeting the [requirements](#requirements), you need a version of
Visual Studio (the
[community edition](https://www.visualstudio.com/vs/visual-studio-express/) is
enough) and a CMake version that's compatible with the Visual Studio version
you're using.

You must also ensure that the msvc versions of dependencies you're using are
placed in the correct folders.

For libsodium that is `c-toxcore/third_party/libsodium`, and for pthreads-w32,
it's `c-toxcore/third_party/pthreads-win32`

Once all of this is done, from the **Developer Command Prompt for VS**, simply
run

```
mkdir _build
cd _build
cmake ..
msbuild ALL_BUILD.vcxproj
```

###### MSYS/Cygwin

Download Cygwin
([32-bit](https://cygwin.com/setup-x86.exe)/[64-bit](https://cygwin.com/setup-x86_64.exe))

Search and select exactly these packages in Devel category:

- mingw64-i686-gcc-core (32-bit) / mingw64-x86_64-gcc-core (64-bit)
- mingw64-i686-gcc-g++ (32-bit) / mingw64-x86_64-gcc-g++ (64-bit)
- make
- cmake
- libtool
- autoconf
- automake
- tree
- curl
- perl
- yasm
- pkg-config

To handle Windows EOL correctly run the following in the Cygwin Terminal:

```sh
echo '
export SHELLOPTS
set -o igncr
' > ~/.bash_profile
```

Download toxcore source code and extract it to a folder.

Open Cygwin Terminal in the toxcore folder and run
`./other/windows_build_script_toxcore.sh` to start the build process.

Toxcore build result files will appear in `/root/prefix/` relatively to Cygwin
folder (default `C:\cygwin64`).

Dependency versions can be customized in
`./other/windows_build_script_toxcore.sh` and described in the section below.

##### Cross-compiling from Linux

These cross-compilation instructions were tested on and written for 64-bit
Ubuntu 16.04. You could generalize them for any Linux system, the only
requirements are that you have Docker version of >= 1.9.0 and you are running
64-bit system.

The cross-compilation is fully automated by a parameterized
[Dockerfile](/other/docker/windows/Dockerfile).

Install Docker

```sh
apt-get update
apt-get install docker.io
```

Get the toxcore source code and navigate to `other/docker/windows`.

Build the container image based on the Dockerfile. The following options are
available to customize the building of the container image.

| Name                  | Description                                         | Expected Value                      | Default Value |
| --------------------- | --------------------------------------------------- | ----------------------------------- | ------------- |
| `SUPPORT_ARCH_i686`   | Support building 32-bit toxcore.                    | "true" or "false" (case sensitive). | true          |
| `SUPPORT_ARCH_x86_64` | Support building 64-bit toxcore.                    | "true" or "false" (case sensitive). | true          |
| `SUPPORT_TEST`        | Support running toxcore automated tests.            | "true" or "false" (case sensitive). | false         |
| `CROSS_COMPILE`       | Cross-compiling. True for Docker, false for Cygwin. | "true" or "false" (case sensitive). | true          |
| `VERSION_OPUS`        | Version of libopus to build toxcore with.           | Numeric version number.             | 1.3.1         |
| `VERSION_SODIUM`      | Version of libsodium to build toxcore with.         | Numeric version number.             | 1.0.18        |
| `VERSION_VPX`         | Version of libvpx to build toxcore with.            | Numeric version number.             | 1.11.0        |

Example of building a container image with options

```sh
cd other/docker/windows
docker build \
  --build-arg SUPPORT_TEST=true \
  -t toxcore \
  .
```

Run the container to build toxcore. The following options are available to
customize the running of the container image.

| Name                 | Description                                                                                | Expected Value                      | Default Value               |
| -------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------- | --------------------------- |
| `ALLOW_TEST_FAILURE` | Don't stop if a test suite fails.                                                          | "true" or "false" (case sensitive). | `false`                     |
| `ENABLE_ARCH_i686`   | Build 32-bit toxcore. The image should have been built with `SUPPORT_ARCH_i686` enabled.   | "true" or "false" (case sensitive). | `true`                      |
| `ENABLE_ARCH_x86_64` | Build 64-bit toxcore. The image should have been built with `SUPPORT_ARCH_x86_64` enabled. | "true" or "false" (case sensitive). | `true`                      |
| `ENABLE_TEST`        | Run the test suite. The image should have been built with `SUPPORT_TEST` enabled.          | "true" or "false" (case sensitive). | `false`                     |
| `EXTRA_CMAKE_FLAGS`  | Extra arguments to pass to the CMake command when building toxcore.                        | CMake options.                      | `-DTEST_TIMEOUT_SECONDS=90` |
| `CROSS_COMPILE`      | Cross-compiling. True for Docker, false for Cygwin.                                        | "true" or "false" (case sensitive). | `true`                      |

Example of running the container with options

```sh
docker run \
  -e ENABLE_TEST=true \
  -e ALLOW_TEST_FAILURE=true \
  -v /path/to/toxcore/sourcecode:/toxcore \
  -v /path/to/where/output/build/result:/prefix \
  --rm \
  toxcore
```

After the build succeeds, you should see the built toxcore libraries in
`/path/to/where/output/build/result`.

## Pre-built binaries

### Linux

Toxcore is packaged by at least by the following distributions: ALT Linux,
[Arch Linux](https://www.archlinux.org/packages/?q=toxcore),
[Fedora](https://apps.fedoraproject.org/packages/toxcore), Mageia, openSUSE,
PCLinuxOS, ROSA and Slackware,
[according to the information from pkgs.org](https://pkgs.org/download/toxcore).
Note that this list might be incomplete and some other distributions might
package it too.
