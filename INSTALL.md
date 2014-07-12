#Install Instructions

- [Installation](#installation)
  - [Unix like](#unix)
  - [OS X](#osx)
    - [Homebrew](#homebrew)
    - [Non-Homebrew](#non-homebrew)
  - [Windows](#windows)
    - [Cross-Compile](#windows-cross-compile)
      - [Setting up a VM](#windows-cross-compile-vm)
      - [Setting up the environment](#windows-cross-compile-environment)
      - [Compiling](#windows-cross-compile-compiling)
    - [Native](#windows-native)
- [Additional](#additional)
  - [Advanced configure options](#aconf)
  - [A/V support](#av)
    - [libtoxav](#libtoxav)
  - [Bootstrap daemon](#bootstrapd)
  - [nTox](#ntox)

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
pkg install net-im/tox
```
Note, if you install from ports select NaCl for performance, and sodium if you want it to be portable.

You should get and install [libsodium](https://github.com/jedisct1/libsodium):
```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.5.0
./autogen.sh
./configure && make check
sudo checkinstall --install --pkgname libsodium --pkgversion 0.5.0 --nodoc
sudo ldconfig
cd ..
```


Or if checkinstall is not easily available for your distribution (e.g., Fedora),
this will install the libs to /usr/local/lib and the headers to /usr/local/include:

```bash
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.5.0
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
./configure --with-libsodium-headers=/usr/local/Cellar/libsodium/0.4.5/include/ --with-libsodium-libs=/usr/local/Cellar/libsodium/0.4.5/lib/
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
  * http://yasm.tortall.net/Download.html
  * https://code.google.com/p/webm/downloads/list
  * http://www.opus-codec.org/downloads/
  * http://www.freedesktop.org/wiki/Software/pkg-config/

You must install yasm before installing libvpx, otherwise libvpx will fail to make correctly.

pkg-config is important for enabling a/v support in tox core, failure to install pkg-config will prevent tox core form finding the required libopus/libvpx libraries. (pkg-config may not configure properly, if you get an error about GLIB, run configure with the following parameter, --with-internal-glib).

Uncompress and install them all. Make sure to follow the README as the instructions change, but they all follow the same pattern below:

```bash
./configure
make
sudo make install
```

Compiling and installing Tox Core

```bash
cd ProjectTox-Core
autoreconf -i
./configure
make
make install
```

If after running ./configure you get an error about core being unable to find libsodium (and you have installed it) run the following in place of ./configure;

./configure --with-libsodium-headers=/usr/local/include/ --with-libsodium-libs=/usr/local/lib

Ensure you set the locations correctly depending on where you installed libsodium on your computer.

If there is a problem with opus (for A/V) and you don't get a libtoxav, then try to set the pkg-config environment variable beforehand:

```
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
```

<a name="windows" />
###Windows:

<a name="windows-cross-compile" />

####Cross-compile

It's a bit challenging to build Tox and all of its dependencies nativly on Windows, so we will show an easier, less error and headache prone method of building it -- cross-compiling.

<a name="windows-cross-compile-vm" />
#####Setting up a VM

We will assume that you don't have any VM running Linux around and will guide you from the ground up.

First, you would need to get a virtual machine and a Linux distribution image file.

For a virtual machine we will use VirtualBox. You can get it [here](https://www.virtualbox.org/wiki/Downloads).

For a Linux distribution we will use Lubuntu 14.04 32-bit, which you can get [here](https://help.ubuntu.com/community/Lubuntu/GetLubuntu).

After you have those downloaded, install the VirtualBox and create a VM in it. The default of 512mb of RAM and 8gb of dynamically-allocated virtual hard drive would be enough.

When you have created the VM, go into its **Settings** -> **System** -> **Processor** and add some cores, if you have any additional available, for faster builds.

Then, go to **Settings** -> **Storage**, click on **Empty** under **Controller: IDE**, click on the little disc icon on the right side of the window, click on **Choose a virtual CD/DVD disk file** and select the downloaded Lubuntu image file.

Start the VM and follow the installation instructions.

After Lubuntu is installed and you have booted into it, in VirtualBox menu on top of the window select **Devices** -> **Insert Guest Additions CD image...**.

Open terminal from **Lubuntu's menu** -> **Accessories**.

Execute:
```bash
sudo apt-get update
sudo apt-get install build-essential -y
cd /media/*/*/
sudo ./VBoxLinuxAdditions.run
```

After that, create a folder called `toxbuild` somewhere on your Windows system. The go to **Devices** -> **Shared Folders Settings...** in the VirtualBox menu, add the `toxbuild` folder there and set **Auto-mount** and **Make Permanent** options.

Execute:
```bash
sudo adduser `whoami` vboxsf
```
Note the use of a [grave accent](http://en.wikipedia.org/wiki/Grave_accent) instead of an apostrophe.

Then just reboot the system with:
```bash
sudo reboot
```

After the system is booted, go to **Devices** -> **Shared Clipboard** and select **Bidirectional**. Now you will be able to copy-paste text between the host and the guest systems.

Now that the virtual machine is all set up, let's move to getting build dependencies and setting up environment variables.

<a name="windows-cross-compile-environment" />
#####Setting up the environment

First we will install all tools that we would need for building:
```bash
sudo apt-get install build-essential libtool autotools-dev automake checkinstall check git yasm pkg-config mingw-w64 -y
```

Then we will define a few variables, **depending on which you will build either 32-bit or 64-bit Tox**.

For 32-bit Tox build, do:
```bash
WINDOWS_TOOLCHAIN=i686-w64-mingw32
LIB_VPX_TARGET=x86-win32-gcc
```

For 64-bit Tox build, do:
```bash
WINDOWS_TOOLCHAIN=x86_64-w64-mingw32
LIB_VPX_TARGET=x86_64-win64-gcc
```

This is the only difference between 32-bit and 64-bit build procedures.

For speeding up the build process do:
```
MAKEFLAGS=j$(nproc)
export MAKEFLAGS
```

And let's make a folder where we will be building everything at
```bash
cd ~
mkdir prefix
cd prefix
PREFIX_DIR=$(pwd)
cd ..
mkdir build
cd build
```

<a name="windows-cross-compile-compiling" />
#####Compiling

Now we will build libraries needed for audio/video: VPX and Opus.

VPX:
```bash
git clone http://git.chromium.org/webm/libvpx.git
cd libvpx
git checkout tags/v1.3.0
CROSS="$WINDOWS_TOOLCHAIN"- ./configure --target="$LIB_VPX_TARGET" --prefix="$PREFIX_DIR" --disable-examples --disable-unit-tests --disable-shared --enable-static
make
make install
cd ..
```

Opus:
```bash
wget http://downloads.xiph.org/releases/opus/opus-1.1.tar.gz
tar -xf opus-1.1.tar.gz
cd opus-1.1
./configure --host="$WINDOWS_TOOLCHAIN" --prefix="$PREFIX_DIR" --disable-extra-programs --disable-doc --disable-shared --enable-static
make
make install
cd ..
```

Now we will build sodium crypto library:
```bash
git clone https://github.com/jedisct1/libsodium/
cd libsodium
git checkout tags/0.4.5
./autogen.sh
./configure --host="$WINDOWS_TOOLCHAIN" --prefix="$PREFIX_DIR" --disable-shared --enable-static
make
make install
cd ..
```

And finally we will build Tox:
```bash
git clone https://github.com/irungentoo/toxcore
cd toxcore
./autogen.sh
./configure --host="$WINDOWS_TOOLCHAIN" --prefix="$PREFIX_DIR" --disable-ntox --disable-tests --disable-testing --with-dependency-search="$PREFIX_DIR" --disable-shared --enable-static
make
make install
cd ..
```

Then we make Tox shared library:
```bash
cd "$PREFIX_DIR"
mkdir tmp
cd tmp
$WINDOWS_TOOLCHAIN-ar x ../lib/libtoxcore.a
$WINDOWS_TOOLCHAIN-ar x ../lib/libtoxav.a
$WINDOWS_TOOLCHAIN-ar x ../lib/libtoxdns.a
$WINDOWS_TOOLCHAIN-gcc -Wl,--export-all-symbols -Wl,--out-implib=libtox.dll.a -shared -o libtox.dll *.o ../lib/*.a /usr/$WINDOWS_TOOLCHAIN/lib/libwinpthread.a -lws2_32 -static-libgcc
```

And we will copy it over to the `toxbuild` directory:
```bash
mkdir -p /media/sf_toxbuild/release/lib
mv libtox.dll* /media/sf_toxbuild/release/lib
mkdir -p /media/sf_toxbuild/release/include
mv ../include/tox /media/sf_toxbuild/release/include
```

That's it. Now you should have `release/lib/libtox.dll` and `release/include/tox/<headers>` in your `toxbuild` directory on the Windows system.

<a name="windows-native" />
####Native

Note that the Native instructions are incomplete, in a sense that they miss instructions needed for adding audio/video support to Tox. You also might stumble upon some unknown MinGW+msys issues while trying to build it.

You should install:
  - [MinGW](http://sourceforge.net/projects/mingw/)

When installing MinGW, make sure to select the MSYS option in the installer.
MinGW will install an "MinGW shell" (you should get a shortcut for it), make sure to perform all operations (i.e., generating/running configure script, compiling, etc.) from the MinGW shell.

First download the source tarball from https://download.libsodium.org/libsodium/releases/ and build it.
Assuming that you got the libsodium-0.5.0.tar.gz release:
```cmd
tar -zxvf libsodium-0.5.0.tar.gz
cd libsodium-0.5.0
./configure
make
make install
cd ..
```

You can also use a precompiled win32 binary of libsodium, however you will have to place the files in places where they can be found, i.e., dll's go to /bin headers to /include and libraries to /lib directories in your MinGW shell.

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

See this [readme](other/bootstrap_daemon/README.md) on how to set up the bootstrap daemon.


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
