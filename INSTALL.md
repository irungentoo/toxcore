##Installation

###Linux:

Build dependencies:

```bash
apt-get install build-essential libtool autotools-dev automake libconfig-dev ncurses-dev cmake checkinstall
```

You should get and install [libsodium](https://github.com/jedisct1/libsodium):
```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.4.2
./autogen.sh
./configure && make check
sudo checkinstall --install --pkgname libsodium --pkgversion 0.4.2 --nodoc
sudo ldconfig
```

Then clone this repo and run:
```bash
mkdir build && cd build
cmake ..
```

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

###OSX:

Much the same as above, remember to install the latest XCode and the developer tools (Preferences -> Downloads -> Command Line Tools).
Users running Mountain Lion and the latest version of XCode (4.6.3) will also need to install libtool, automake and autoconf.
They are easy enough to install, grab them from http://www.gnu.org/software/libtool/, http://www.gnu.org/software/autoconf/ and http://www.gnu.org/software/automake/, then follow these steps for each:

```bash
./configure
make
sudo make install
```

Do not install them from macports (or any dependencies for that matter) as they get shoved in the wrong directory
and make your life more annoying.

Another thing you may want to install is the latest gcc, this caused me a few problems as XCode from 4.3
no longer includes gcc and instead uses LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)'s C compiler
  - [CMake](http://www.cmake.org/cmake/resources/software.html)

You have to [modify your PATH environment variable](http://www.computerhope.com/issues/ch000549.htm) so that it contains MinGW's bin folder path. With default settings, the bin folder is located at `C:\MinGW\bin`, which means that you would have to append `;C:\MinGW\bin` to the PATH variable.

Then you should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

After that you should get precompiled package of libsodium from [here](https://download.libsodium.org/libsodium/releases/libsodium-win32-0.4.2.tar.gz) and extract the archive into this repo's root. That is, `sodium` folder should be along with `core`, `testing` and other folders.

Navigate in `cmd` to this repo and run:
```cmd
mkdir build && cd build
cmake -G "MinGW Makefiles" ..
```

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
