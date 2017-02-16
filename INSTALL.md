# Installation instructions

These instructions will guide you through the process of building and installing the toxcore library and its components, as well as getting already pre-built binaries.

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
  - [Windows](#windows-1)

## Overview

### Components

#### Main

This repository, although called `toxcore`, in fact contains several libraries besides `toxcore` which complement it, as well as several executables. However, note that although these are separate libraries, at the moment, when building the libraries, they are all merged into a single `toxcore` library. Here is the full list of the main components that can be built using the CMake, their dependencies and descriptions.

| Name           | Type       | Dependencies                                  | Platform       | Description                                                                |
|----------------|------------|-----------------------------------------------|----------------|----------------------------------------------------------------------------|
| toxcore        | Library    | libnacl or libsodium, libm, libpthread, librt | Cross-platform | The main Tox library that provides the messenger functionality.            |
| toxav          | Library    | libtoxcore, libopus, libvpx                   | Cross-platform | Provides audio/video functionality.                                        |
| toxencryptsave | Library    | libtoxcore, libnacl or libsodium              | Cross-platform | Provides encryption of Tox profiles (savedata), as well as arbitrary data. |
| DHT_bootstrap  | Executable | libtoxcore                                    | Cross-platform | A simple DHT bootstrap node.                                               |
| tox-bootstrapd | Executable | libtoxcore, libconfig                         | Unix-like      | Highly configurable DHT bootstrap node daemon (systemd, SysVinit, Docker). |

#### Secondary

There are some testing programs that you might find interesting. Note that they are not intended for the real-world use and are not coded to the high security standards, so use them on your own risk.

| Name        | Type       | Dependencies           | Platform  | Description                                                                                                                             |
|-------------|------------|------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| irc_syncbot | Executable | libtoxcore             | Unix-like | Bot that synchronizes an IRC channel and a Tox group chat (conference).                                                                      |
| tox_shell   | Executable | libtoxcore, libutil    | Unix-like | Proof of concept SSH-like server software using Tox. Testing program, not intended for actual use.                                      |
| tox_sync    | Executable | libtoxcore             | Unix-like | Bittorrent-sync-like software using Tox. Syncs two directories together.                                                                |

There are also some programs that are not plugged into the CMake build system which you might find interesting. You would need to build those programs yourself. These programs reside in [`other/fun`](other/fun) directory.

| Name                | Type       | Dependencies         | Platform       | Description                                                                                                                                                            |
|---------------------|------------|----------------------|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| bootstrap_node_info | Script     | python3              | Cross-platform | Script for getting version and Message Of The Day (MOTD) information from a DHT bootstrap node.                                                                        |
| cracker             | Executable | libnacl or libsodium | Cross-platform | Tries to find a curve25519 key pair, hex representation of the public key of which starts with the specified byte sequence.                                            |
| strkey              | Executable | libsodium            | Cross-platform | Tries to find a curve25519 key pair, hex representation of the public key of which contains a specified byte pattern at the specified position or at any position.     |
| make-funny-savefile | Script     | python               | Cross-platform | Generates Tox profile file (savedata file) with provided key pair. Useful for generating Tox profiles from the output of cracker or strkey programs.                   |
| sign                | Executable | libsodium            | Cross-platform | Program for ed25519 file signing.                                                                                                                                      |

## Building

### Requirements

#### Library dependencies

Library dependencies are listed in the [components](#components) table. The dependencies need to be satisfied for the components to be built. Note that if you don't have a dependency for some component, e.g. you don't have `libopus` installed required for building `toxav` component, building of that component is silently disabled.

#### Compiler requirements

The supported compilers are GCC, Clang and MinGW.

In theory, any compiler that fully supports C99 and accepts GCC flags should work.

There is a partial and experimental support of Microsoft Visual C++ compiler. We welcome any patches that help improve it.

You should have a C99 compatible compiler in order to build the main components. The secondary components might require the compiler to support GNU extensions.

#### Build system requirements

To build the main components you need to have CMake of at least 2.8.6 version installed. You also need to have pkg-config installed, the build system uses it to find dependency libraries.

There is some experimental accommodation for building natively on Windows, i.e. without having to use MSYS/Cygwin and pkg-config, but it uses exact hardcoded paths for finding libraries and supports building only of some of toxcore components, so your mileage might vary.

### CMake options

There are some options that are available to configure the build.

| Name                 | Description                                                                                   | Expected Value                             | Default Value                                     |
|----------------------|-----------------------------------------------------------------------------------------------|--------------------------------------------|---------------------------------------------------|
| ASAN                 | Enable address-sanitizer to detect invalid memory accesses.                                   | ON or OFF                                  | OFF                                               |
| BOOTSTRAP_DAEMON     | Enable building of tox-bootstrapd, the DHT bootstrap node daemon. For Unix-like systems only. | ON or OFF                                  | ON                                                |
| BUILD_AV_TEST        | Build toxav test.                                                                             | ON or OFF                                  | ON                                                |
| BUILD_TOXAV          | Whether to build the tox AV library.                                                          | ON or OFF                                  | ON                                                |
| CMAKE_INSTALL_PREFIX | Path to where everything should be installed.                                                 | Directory path.                            | Platform-dependent. Refer to CMake documentation. |
| DEBUG                | Enable assertions and other debugging facilities.                                             | ON or OFF                                  | OFF                                               |
| DHT_BOOTSTRAP        | Enable building of DHT_bootstrap                                                              | ON or OFF                                  | ON                                                |
| ENABLE_SHARED        | Build shared (dynamic) libraries for all modules.                                             | ON or OFF                                  | ON                                                |
| ENABLE_STATIC        | Build static libraries for all modules.                                                       | ON or OFF                                  | ON                                                |
| ERROR_ON_WARNING     | Make compilation error on a warning.                                                          | ON or OFF                                  | OFF                                               |
| FORMAT_TEST          | Require the format_test to be executed; fail cmake if it can't.                               | ON or OFF                                  | OFF                                               |
| STRICT_ABI           | Enforce strict ABI export in dynamic libraries.                                               | ON or OFF                                  | OFF                                               |
| TEST_TIMEOUT_SECONDS | Limit runtime of each test to the number of seconds specified.                                | Positive number or nothing (empty string). | Empty string.                                     |
| TRACE                | Enable TRACE level logging (expensive, for network debugging).                                | ON or OFF                                  | OFF                                               |
| USE_IPV6             | Use IPv6 in tests.                                                                            | ON or OFF                                  | ON                                                |
| WARNINGS             | Enable additional compiler warnings.                                                          | ON or OFF                                  | ON                                                |

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
  -D DEBUG=ON \
  -D CMAKE_INSTALL_PREFIX=/opt \
  -D TEST_TIMEOUT_SECONDS=120 \
  ..
```

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

There are currently no instructions on how to build toxcore on Windows host in Microsoft Visual Studio's Developer Command Prompt. Contribution of the instructions is welcome!

###### MSYS/Cygwin

There are currently no instructions on how to build toxcore on Windows host in MSYS/Cygwin. Contribution of the instructions is welcome!

##### Cross-compiling from Linux

These cross-compilation instructions were tested on and written for 64-bit Ubuntu 16.04. You could generalize them for any Linux system, the only requirements are that you have Docker version of >= 1.9.0 and you are running 64-bit system.

The cross-compilation is fully automated by a parameterized [Dockerfile](/other/docker/windows/Dockerfile).

Install Docker

```sh
apt-get update
apt-get install docker.io
```

Get the toxcore source code and navigate to `other/docker/windows`.

Build the container image based on the Dockerfile. The following options are available to customize the building of the container image.

| Name                | Description                                                    | Expected Value                      | Default Value |
|---------------------|----------------------------------------------------------------|-------------------------------------|---------------|
| SUPPORT_ARCH_i686   | Support building 32-bit toxcore.                               | "true" or "false" (case sensitive). | true          |
| SUPPORT_ARCH_x86_64 | Support building 64-bit toxcore.                               | "true" or "false" (case sensitive). | true          |
| SUPPORT_TEST        | Support running toxcore automated tests.                       | "true" or "false" (case sensitive). | false         |
| VERSION_CHECK       | Version of libcheck. Needed only when SUPPORT_TEST is enabled. | Git branch name.                    | 0.12.0        |
| VERSION_OPUS        | Version of libopus to build toxcore with.                      | Git branch name.                    | v1.2.1        |
| VERSION_SODIUM      | Version of libsodium to build toxcore with.                    | Git branch name.                    | 1.0.16        |
| VERSION_VPX         | Version of libvpx to build toxcore with.                       | Git branch name.                    | v1.6.1        |

Example of building a container image with options

```sh
cd other/docker/windows
docker build \
  --build-arg SUPPORT_TEST=true \
  --build-arg VERSION_CHECK=0.11.0 \
  -t toxcore \
  .
```

Run the container to build toxcore. The following options are available to customize the running of the container image.

| Name               | Description                                                                              | Expected Value                      | Default Value                                                      |
|--------------------|------------------------------------------------------------------------------------------|-------------------------------------|--------------------------------------------------------------------|
| ALLOW_TEST_FAILURE | Don't stop if a test suite fails.                                                        | "true" or "false" (case sensitive). | false                                                              |
| ENABLE_ARCH_i686   | Build 32-bit toxcore. The image should have been built with SUPPORT_ARCH_i686 enabled.   | "true" or "false" (case sensitive). | true                                                               |
| ENABLE_ARCH_x86_64 | Build 64-bit toxcore. The image should have been built with SUPPORT_ARCH_x86_64 enabled. | "true" or "false" (case sensitive). | true                                                               |
| ENABLE_TEST        | Run the test suite. The image should have been built with SUPPORT_TEST enabled.          | "true" or "false" (case sensitive). | false                                                              |
| EXTRA_CMAKE_FLAGS  | Extra arguments to pass to the CMake command when building toxcore.                      | CMake options.                      | "-DWARNINGS=OFF -DBOOTSTRAP_DAEMON=OFF -DTEST_TIMEOUT_SECONDS=300" |

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

After the build succeeds, you should see the built toxcore libraries in `/path/to/where/output/build/result`.

## Pre-built binaries

### Linux

Toxcore is packaged by at least by the following distributions: ALT Linux, [Arch Linux](https://www.archlinux.org/packages/?q=toxcore), [Fedora](https://apps.fedoraproject.org/packages/toxcore), Mageia, openSUSE, PCLinuxOS, ROSA and Slackware, [according to the information from pkgs.org](https://pkgs.org/download/toxcore). Note that this list might be incomplete and some other distributions might package it too.

Debian and Ubuntu packages are available in [tox.chat's package repository](https://tox.chat/download.html#gnulinux).

### Windows

There are nightly cross-compiled binaries available on Jenkins.

|        | Shared                                                                                                                                                                              | Static                                                                                                                                                                              |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 32-bit | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86_shared_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86_shared_release.zip)       | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86_static_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86_static_release.zip)       |
| 64-bit | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86-64_shared_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86-64_shared_release.zip) | [Download](https://build.tox.chat/job/libtoxcore-toktok_build_windows_x86-64_static_release/lastSuccessfulBuild/artifact/libtoxcore-toktok_build_windows_x86-64_static_release.zip) |
