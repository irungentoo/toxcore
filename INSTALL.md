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
sudo apt-get install build-essential libtool autotools-dev automake libconfig-dev ncurses-dev checkinstall check
```

On Fedora:

```bash
yum groupinstall "Development Tools"
yum install libtool autoconf automake libconfig-devel ncurses-devel check check-devel
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
autoreconf -i
./configure
make
sudo make install
```
Advance configure options:
  - --prefix=/where/to/install
  - --with-libsodium-headers=/path/to/libsodium/include/
  - --with-libsodium-libs=/path/to/sodiumtest/lib/
  - --enable-silent-rules less verbose build output (undo: "make V=1")
  - --disable-silent-rules verbose build output (undo: "make V=0")
  - --disable-tests build unit tests (default: auto)
  - --disable-ntox build nTox client (default: auto)
  - --disable-dht-bootstrap-daemon build DHT bootstrap daemon (default: auto)
  - --enable-shared[=PKGS]  build shared libraries [default=yes]
  - --enable-static[=PKGS]  build static libraries [default=yes]

<a name="osx" />
###OS X:

You need the latest XCode with the Developer Tools (Preferences -> Downloads -> Command Line Tools).
The following libraries are required along with libsodium and cmake for Mountain Lion and XCode 4.6.3 install libtool, automake and autoconf. You can download them with Homebrew, or install them manually.

There are no binaries/executables going to /bin/ or /usr/bin/ now. Everything is compiled and ran from the inside your local branch. See [Usage](#usage) below.
<a name="homebrew" />
####Homebrew:
```
brew install libtool automake autoconf libconfig libsodium check
```
Then clone this repo and generate makefile:
```bash
git clone git://github.com/irungentoo/ProjectTox-Core.git
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```
Advance configure options:
  - --prefix=/where/to/install
  - --with-libsodium-headers=/path/to/libsodium/include/
  - --with-libsodium-libs=/path/to/sodiumtest/lib/
  - --BUILD_DHT_BOOTSTRAP_DAEMON="yes"
  - --BUILD_NTOX="yes"
  - --BUILD_TESTS="yes"
  - --enable-silent-rules less verbose build output (undo: "make V=1")
  - --disable-silent-rules verbose build output (undo: "make V=0")
  - --disable-tests build unit tests (default: auto)
  - --disable-ntox build nTox client (default: auto)
  - --disable-dht-bootstrap-daemon build DHT bootstrap daemon (default: auto)
  - --enable-shared[=PKGS]  build shared libraries [default=yes]
  - --enable-static[=PKGS]  build static libraries [default=yes]

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

Then generate the makefile:
```bash
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```
Advance configure options:
  - --prefix=/where/to/install
  - --with-libsodium-headers=/path/to/libsodium/include/
  - --with-libsodium-libs=/path/to/sodiumtest/lib/
  - --BUILD_DHT_BOOTSTRAP_DAEMON="yes"
  - --BUILD_NTOX="yes"
  - --BUILD_TESTS="yes"
  - --enable-silent-rules less verbose build output (undo: "make V=1")
  - --disable-silent-rules verbose build output (undo: "make V=0")
  - --disable-tests build unit tests (default: auto)
  - --disable-ntox build nTox client (default: auto)
  - --disable-dht-bootstrap-daemon build DHT bootstrap daemon (default: auto)
  - --enable-shared[=PKGS]  build shared libraries [default=yes]
  - --enable-static[=PKGS]  build static libraries [default=yes]

Do not install them from macports (or any dependencies for that matter) as they get shoved in the wrong directory
(or the wrong version gets installed) and make your life more annoying.

Another thing you may want to install is the latest gcc, this caused me a few problems as XCode from 4.3
no longer includes gcc and instead uses LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

<a name="windows" />
###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)'s C compiler
  - [check] (http://check.sourceforge.net/)

You have to [modify your PATH environment variable](http://www.computerhope.com/issues/ch000549.htm) so that it contains MinGW's bin folder path. With default settings, the bin folder is located at `C:\MinGW\bin`, which means that you would have to append `;C:\MinGW\bin` to the PATH variable.

Then you should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

After that you should get precompiled package of libsodium from [here](https://download.libsodium.org/libsodium/releases/libsodium-win32-0.4.2.tar.gz) and extract the archive into this repo's root. That is, `sodium` folder should be along with `core`, `testing` and other folders.

Then clone this repo and generate makefile:
```cmd
git clone git://github.com/irungentoo/ProjectTox-Core.git
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```
Advance configure options:
  - --prefix=/where/to/install
  - --with-libsodium-headers=/path/to/libsodium/include/
  - --with-libsodium-libs=/path/to/sodiumtest/lib/
  - --BUILD_DHT_BOOTSTRAP_DAEMON="yes"
  - --BUILD_NTOX="yes"
  - --BUILD_TESTS="yes"
  - --enable-silent-rules less verbose build output (undo: "make V=1")
  - --disable-silent-rules verbose build output (undo: "make V=0")
  - --disable-tests build unit tests (default: auto)
  - --disable-ntox build nTox client (default: auto)
  - --disable-dht-bootstrap-daemon build DHT bootstrap daemon (default: auto)
  - --enable-shared[=PKGS]  build shared libraries [default=yes]
  - --enable-static[=PKGS]  build static libraries [default=yes]

<a name="Clients" />
####Clients:
While [Toxic](https://github.com/tox/toxic) is no longer in core, a list of Tox clients are located in our [wiki](http://wiki.tox.im/client)
