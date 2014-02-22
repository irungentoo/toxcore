#Install Instructions

- [Installation](#installation)
    - [Unix like](#unix)
    - [OS X](#osx)
      - [Homebrew](#homebrew)
      - [Non-Homebrew](#non-homebrew)
    - [Windows](#windows)

- [Additional](#additional)
    - [Advanced configure options] (#aconf)
    - [A/V support](#av)
      - [libtoxav] (#libtoxav)
      - [Test phone] (#phone)
    - [Bootstrap daemon] (#bootstrapd)
    - [nTox] (#ntox)

<a name="installation" />
##Installation

<a name="unix" />
###Most Unix like OSes:

Build dependencies:

Note: package fetching commands may vary by OS.

On Ubuntu: 

```bash
sudo apt-get install build-essential libtool autotools-dev automake checkinstall check git yasm
```

On Fedora:

```bash
yum groupinstall "Development Tools"
yum install libtool autoconf automake check check-devel
```

On SunOS: 

```pfexcec 
pkg install autoconf automake gcc-47
```
On FreeBSD 10+:

```tcsh
pkg install automake autoconf
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

If your default prefix is /usr/local and you happen to get an error that says "error while loading shared libraries: libtoxcore.so.0: cannot open shared object file: No such file or directory", then you can try running ```sudo ldconfig```. If that doesn't fix it, run:
```
echo '/usr/local/lib/' | sudo tee -a /etc/ld.so.conf.d/locallib.conf
sudo ldconfig
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


<a name="osx" />
###OS X:

You need the latest XCode with the Developer Tools (Preferences -> Downloads -> Command Line Tools).
The following libraries are required along with libsodium and cmake for Mountain Lion and XCode 4.6.3 install libtool, automake and autoconf. You can download them with Homebrew, or install them manually.

There are no binaries/executables going to /bin/ or /usr/bin/ now. Everything is compiled and ran from the inside your local branch. See [Usage](#usage) below.
<a name="homebrew" />
####Homebrew:
To install from the formula:
```bash
brew tap Tox/tox
brew install --HEAD libtoxcore
```

To do it manually:
```
brew install libtool automake autoconf libsodium check
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

If execution fails with errors like "dyld: Library not loaded: /opt/tox-im/lib/libtoxcore.0.dylib", you may need to specify libsodium path:

Determine paths:
```
brew list libsodium
```

Configure include and lib folder and build again:
```bash
./configure--with-libsodium-headers=/usr/local/Cellar/libsodium/0.4.5/include/ --with-libsodium-libs=/usr/local/Cellar/libsodium/0.4.5/lib/
make
make install
```


<a name="non-homebrew" />
####Non-homebrew:

Grab the following packages:
  * https://gnu.org/software/libtool/
  * https://gnu.org/software/autoconf/ 
  * https://gnu.org/software/automake/
  * https://github.com/jedisct1/libsodium
  * http://check.sourceforge.net/

Uncompress and install them all. Make sure to follow the README as the instructions change, but they all follow the same pattern below:

```bash
./configure
make
sudo make install
```

In your local TOX repository:

Then generate makefile, build and install tox:
```bash
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```

Do not install them from macports (or any dependencies for that matter) as they get shoved in the wrong directory
(or the wrong version gets installed) and make your life more annoying.

Another thing: you may want to install is the latest gcc. This caused me a few problems as XCode from 4.3
no longer includes gcc and instead uses LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

<a name="windows" />
###Windows:

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)

When installing MinGW, make sure to select the MSYS option in the installer.
MinGW will install an "MinGW shell" (you should get a shortcut for it), make sure to perform all operations (i.e. generating/running configure script, compiling, etc.) from the MinGW shell.

First download the source tarball from https://download.libsodium.org/libsodium/releases/ and build it.
Assuming that you got the libsodium-0.4.2.tar.gz release:
```cmd
tar -zxvf libsodium-0.4.2.tar.gz
cd libsodium-0.4.2
./configure
make
make install
cd ..
```

You can also use a precompiled win32 binary of libsodium, however you will have to place the files in places where they can be found, i.e. dll's go to /bin headers to /include and libraries to /lib directories in your MinGW shell.

Next, install ProjectTox-Core library, should either clone this repo by using git, or just download a [zip of current Master branch](https://github.com/irungentoo/ProjectTox-Core/archive/master.zip) and extract it somewhere.

Assuming that you now have the sources in the ProjectTox-Core directory:

```cmd
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```

<a name="Clients" />
####Clients:
While [Toxic](https://github.com/tox/toxic) is no longer in core, a list of Tox clients are located in our [wiki](http://wiki.tox.im/client)





<a name="additional" />
##Additional



<a name="aconf" />
###Advanced configure options:

  - --prefix=/where/to/install
  - --with-libsodium-headers=/path/to/libsodium/include/
  - --with-libsodium-libs=/path/to/sodiumtest/lib/
  - --enable-silent-rules less verbose build output (undo: "make V=1")
  - --disable-silent-rules verbose build output (undo: "make V=0")
  - --disable-tests build unit tests (default: auto)
  - --disable-av disable A/V support (default: auto) see: [libtoxav](#libtoxav)
  - --enable-phone build phone (default: no) see: [Test phone](#phone)
  - --enable-ntox build nTox client (default: no) see: [nTox](#ntox)
  - --enable-daemon build DHT bootstrap daemon (default=no) see: [Bootstrap daemon](#bootstrapd)
  - --enable-shared[=PKGS]  build shared libraries [default=yes]
  - --enable-static[=PKGS]  build static libraries [default=yes]


<a name="av" />
###A/V support:

<a name="libtoxav" />
####libtoxav:

'libtoxav' is needed for A/V support and it's enabled by default. You can disable it by adding --disable-av argument to ./configure script like so: 
```bash
./configure --disable-av
```

There are 2 dependencies required for libtoxav: libopus and libvpx. If they are not installed A/V support is dropped.

Install on fedora:
```bash
yum install libopus-devel libvpx-devel
```

Install on ubuntu:
```bash
sudo apt-get install libopus-dev libvpx-dev
```
If you get the "Unable to locate package libopus-dev" message, add the following ppa and try again:
```bash
sudo add-apt-repository ppa:ubuntu-sdk-team/ppa && sudo apt-get update && sudo apt-get dist-upgrade
```

Install from source (example for most unix-like OS's):

libvpx:
```bash
git clone http://git.chromium.org/webm/libvpx.git
cd libvpx
./configure
make -j3
sudo make install
cd ..
```

libopus:
```bash
wget http://downloads.xiph.org/releases/opus/opus-1.0.3.tar.gz
tar xvzf opus-1.0.3.tar.gz
cd opus-1.0.3
./configure
make -j3
sudo make install
cd ..
```


<a name="phone" />
####Test phone:

Test phone is disabled by default. You can enable it by adding --enable-phone argument to ./configure script like so:
```bash
./configure --enable-phone
```
It can be compiled with or without video capturing enabled. There are 4 dependencies for phone: openal, ffmpeg, sdl and swscale. If any of the later 3 are not installed video support is dropped.

Install on fedora:
```bash
yum install libopenal-devel libswscale-devel SDL*
```

Install on ubuntu:
```bash
sudo apt-get install libopenal-dev libswscale-dev libsdl-dev
```

Now grap recent [FFmpeg](https://git.videolan.org/?p=ffmpeg.git) libraries and install them:
```bash
git clone git://source.ffmpeg.org/ffmpeg.git
cd ffmpeg
git checkout n2.0.2
./configure --prefix=`pwd`/install --disable-programs
make && make install
cd ..
```

You are now ready to compile with phone!

Note: Don't forget to run core configure like so:
```bash
./configure --with-dependency-search=`pwd`/../ffmpeg/install
```
before compiling the phone.


<a name="bootstrapd" />
###Bootstrap daemon:

Daemon is disabled by default. You can enable it by adding --enable-daemon argument to ./configure script like so:
```bash
./configure --enable-daemon
```
There is one dependency required for bootstrap daemon: `libconfig-dev` >= 1.4.

Install on fedora:
```bash
yum install libconfig-devel
```

Install on ubuntu:
```bash
sudo apt-get install libconfig-dev
```

OS X homebrew:
```
brew install libconfig
```
OS X non-homebrew:
Grab the following [package] (http://www.hyperrealm.com/libconfig/), uncompress and install

See this [readme](other\bootstrap_daemon\README.md) on how to set up the bootstrap daemon.


<a name="ntox" />
###nTox test cli:

nTox is disabled by default. You can enable it by adding --enable-ntox argument to ./configure script like so:
```bash
./configure --enable-ntox
```
There is one dependency required for nTox: libncurses.

Install on fedora:
```bash
yum install ncurses-devel
```

Install on ubuntu:
```bash
sudo apt-get install ncurses-dev
```

