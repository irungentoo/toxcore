Install Instructions
====================

Linux
---------

First, install the build dependencies ::

    bash apt-get install build-essential libtool autotools-dev automake libconfig-dev ncurses-dev cmake checkinstall

.. note :: ``libconfig-dev`` should be >= 1.4.


Then you'll need a recent version of `libsodium <https://github.com/jedisct1/libsodium>`_ ::

    git clone git://github.com/jedisct1/libsodium.git 
    cd libsodium 
    git checkout tags/0.4.2 
    ./autogen.sh
    ./configure && make check
    sudo checkinstall --install --pkgname libsodium --pkgversion 0.4.2 --nodoc
    sudo ldconfig``

Finally, fetch the Tox source code and run cmake ::
    
    git clone git://github.com/irungentoo/ProjectTox-Core.git
    cd ProjectTox-Core && mkdir build && cd build
    cmake ..

Then you can build any of the files in `/testing`_ and `/other`_ that are currently
supported on your platform by running ::

    make name_of_c_file

For example, to build `Messenger_test.c`_ you would run ::

    make Messenger_test


Or you could just build everything that is supported on your platform by
running :: 
    bash make

OS X
------

Homebrew
~~~~~~~~~~
::

    brew install libtool automake autoconf libconfig libsodium cmake 
    cmake . 
    make
    sudo make install

Non-homebrew
~~~~~~~~~~~~

Much the same as Linux, remember to install the latest XCode and the
developer tools (Preferences -> Downloads -> Command Line Tools). Users
running Mountain Lion and the latest version of XCode (4.6.3) will also
need to install libtool, automake and autoconf. They are easy enough to
install, grab them from http://www.gnu.org/software/libtool/,
http://www.gnu.org/software/autoconf/ and
http://www.gnu.org/software/automake/, then follow these steps for each:

::

    ./configure
    make
    sudo make install

Do not install them from macports (or any dependencies for that matter)
as they get shoved in the wrong directory and make your life more
annoying.

Another thing you may want to install is the latest gcc, this caused me
a few problems as XCode from 4.3 no longer includes gcc and instead uses
LLVM-GCC, a nice install guide can be found at
http://caiustheory.com/install-gcc-421-apple-build-56663-with-xcode-42

Windows
---------

You should install: 

* `MinGW <http://sourceforge.net/projects/mingw/>`_'s C compiler 
* `CMake <http://www.cmake.org/cmake/resources/software.html>`_

You have to `modify your PATH environment
variable <http://www.computerhope.com/issues/ch000549.htm>`_ so that it
contains MinGW's bin folder path. With default settings, the bin folder
is located at ``C:\MinGW\bin``, which means that you would have to
append ``;C:\MinGW\bin`` to the PATH variable.

Then you should either clone this repo by using git, or just download a
`zip of current Master
branch <https://github.com/irungentoo/ProjectTox-Core/archive/master.zip>`_
and extract it somewhere.

After that you should get precompiled package of libsodium from
`here <https://download.libsodium.org/libsodium/releases/libsodium-win32-0.4.2.tar.gz>`_
and extract the archive into this repo's root. That is, ``sodium``
folder should be along with ``core``, ``testing`` and other folders.

Navigate in ``cmd`` to this repo and run::

    mkdir build && cd build 
    cmake -G "MinGW Makefiles" ..

Then you can build any of the `/testing`_ and `/other`_ that are currently
supported on your platform by running::

    mingw32-make name_of_c_file
    
For example, to build `Messenger_test.c`_ you would run::

    mingw32-make Messenger_test``

Or you could just build everything that is supported on your platform by
running::

    mingw32-make


.. _/testing: https://github.com/irungentoo/ProjectTox-Core/tree/master/testing
.. _/other: https://github.com/irungentoo/ProjectTox-Core/tree/master/other

.. _Messenger_test.c: https://github.com/irungentoo/ProjectTox-Core/tree/master/other/Messanger_test.c
