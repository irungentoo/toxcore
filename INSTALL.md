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
cmake CMakeLists.txt
```

Then you can build any of the [`/testing`](/testing) and [`/other`](/other) by running:
```bash
make name_of_c_file
```
For example, to build [`Messenger_test.c`](/others/Messenger_test.c) you would run:
```bash
make Messenger_test
```

###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)'s C compiler
  - [CMake](http://www.cmake.org/cmake/resources/software.html)

Then you should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

After that you should get precompiled packages of libsodium from [here](https://download.libsodium.org/libsodium/releases/) and extract the archive into this repo's root. That is, `sodium` folder should be along with `core`, `testing` and other folders.

Navigate in `cmd` to this repo and run:
```cmd
cmake -G "MinGW Makefiles" CMakeLists.txt
```

Then you can build any of the [`/testing`](/testing) and [`/other`](/other) by running:
```cmd
mingw32-make name_of_c_file
```
For example, to build [`Messenger_test.c`](/others/Messenger_test.c) you would run:
```cmd
mingw32-make Messenger_test
```