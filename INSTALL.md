##Installation

###Linux:

You should get and install [libsodium](https://github.com/jedisct1/libsodium):
```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.4.2
./autogen.sh
./configure && make check
sudo make install
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
Users running Mountain Lion and the latest version of XCode (4.6.3) will also need to install libtool
Libtool is easy enough to install, grab it from http://www.gnu.org/software/libtool/ and:

./configure
make
sudo make install

Do not install it from macports (or any dependencies for that matter) as they get shoved in the wrong directory
and make your life more annoying.

Another thing you may want to install is the latest gcc, this caused me a few problems as XCode from 4.3
no longer includes gcc and instead uses LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)'s C compiler
  - [CMake](http://www.cmake.org/cmake/resources/software.html)

Then you should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

After that you should get precompiled packages of libsodium from [here](https://download.libsodium.org/libsodium/releases/) and extract the archive into this repo's root. That is, `sodium` folder should be along with `core`, `testing` and other folders.

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
