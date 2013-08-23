#Install Instructions

- [Installation](#installation)
    - [Linux](#linux)
    - [OS X](#osx)
      - [Homebrew](#homebrew)
      - [Non-Homebrew](#non-homebrew)
    - [Windows](#windows)

<a name="installation" />
##Installation

<a name="linux" />
###Linux:

Build dependencies:

```bash
apt-get install build-essential libtool autotools-dev automake libconfig-dev ncurses-dev cmake checkinstall check
```

On Fedora:

```bash
yum groupinstall "Development Tools"
yum install libtool autoconf automake libconfig-devel ncurses-devel cmake check check-devel
```

Note that `libconfig-dev` should be >= 1.4.

You should get and install [libsodium](https://github.com/jedisct1/libsodium):
```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.4.2
./autogen.sh
./configure && make check
sudo checkinstall --install --pkgname libsodium --pkgversion 0.4.2 --nodoc
sudo ldconfig
cd ..
```

Or if checkinstall is not easily available for your distribution (e.g. Fedora), 
this will install the libs to /usr/local/lib and the headers to /usr/local/include:

```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.4.2
./autogen.sh
./configure
make check
sudo make install
cd ..
```


Then clone this repo and generate makefile:
```bash
git clone git://github.com/irungentoo/ProjectTox-Core.git
cd ProjectTox-Core
mkdir build && cd build
cmake ..
```
Advance cmake options:
  - `-DUSE_NACL=ON` (default `OFF`) � Use NaCl library instead of libsodium.
   
Note that you should call cmake on the root [`CMakeLists.txt`](/CMakeLists.txt) file only.

Then you can build any of the [`/testing`](/testing) and [`/other`](/other) that are currently supported on your platform by running:
```bash
make name_of_c_file
```
For example, to build [`Messenger_test.c`](/others/Messenger_test.c) you would run:
```bash
make Messenger_test
```

Or you could just build everything that is supported on your platform by running:
```bash
make
```

<a name="osx" />
###OS X:

You need the latest XCode with the Developer Tools (Preferences -> Downloads -> Command Line Tools).
The following libraries are required along with libsodium and cmake for Mountain Lion and XCode 4.6.3 install libtool, automake and autoconf. You can download them with Homebrew, or install them manually.

There are no binaries/executables going to /bin/ or /usr/bin/ now. Everything is compiled and ran from the inside your local branch. See [Usage](#usage) below.

<a name="homebrew" />
####Homebrew:
```
brew install libtool automake autoconf libconfig libsodium cmake check
cmake .
make
```

<a name="non-homebrew" />
####Non-homebrew:

Grab the following packages:
  * http://www.gnu.org/software/libtool/
  * http://www.gnu.org/software/autoconf/ 
  * http://www.gnu.org/software/automake/
  * http://www.cmake.org/
  * https://github.com/jedisct1/libsodium
  * http://www.hyperrealm.com/libconfig/
  * http://check.sourceforge.net/

Uncompress and install them all. Make sure to follow the README as the instructions change, but they all follow the same pattern below:

```bash
./configure
make
sudo make install
```

In your local TOX repository:

```bash
cmake .
make
```

Do not install them from macports (or any dependencies for that matter) as they get shoved in the wrong directory
(or the wrong version gets installed) and make your life more annoying.

Another thing you may want to install is the latest gcc, this caused me a few problems as XCode from 4.3
no longer includes gcc and instead uses LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

<a name="windows" />
###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)'s C compiler
  - [CMake](http://www.cmake.org/cmake/resources/software.html)
  - [check] (http://check.sourceforge.net/)

You have to [modify your PATH environment variable](http://www.computerhope.com/issues/ch000549.htm) so that it contains MinGW's bin folder path. With default settings, the bin folder is located at `C:\MinGW\bin`, which means that you would have to append `;C:\MinGW\bin` to the PATH variable.

Then you should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

After that you should get precompiled package of libsodium from [here](https://download.libsodium.org/libsodium/releases/libsodium-win32-0.4.2.tar.gz) and extract the archive into this repo's root. That is, `sodium` folder should be along with `core`, `testing` and other folders.

Navigate in `cmd` to this repo and run:
```cmd
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
```
Advance cmake options:
  - `-DSHARED_TOXCORE=ON` (default OFF) � Build Core as a shared library.
  - `-DSHARED_LIBSODIUM=ON` (default OFF) � Link libsodium as a shared library.

Note that you should call cmake on the root [`CMakeLists.txt`](/CMakeLists.txt) file only.

Then you can build any of the [`/testing`](/testing) and [`/other`](/other) that are currently supported on your platform by running:
```cmd
mingw32-make name_of_c_file
```
For example, to build [`Messenger_test.c`](/others/Messenger_test.c) you would run:
```cmd
mingw32-make Messenger_test
```

Or you could just build everything that is supported on your platform by running:
```bash
mingw32-make
```

