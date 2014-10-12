#!/usr/bin/env bash
# written by Lubo Diakov
# hard coded toxcore directory, replace with other path or variable as needed
cd ~/Downloads/toxcore
echo "Now working in:"`pwd`

# must have working git binary, and have done git clone at least once before
git pull
echo "If git pull responds: Already up-to-date. you can cancel the build"
echo "by typing anything except y or Y below"
read -p "Continue with build? (enter y to continue): " Last_Chance

# blah blah
if [[ $Last_Chance = [Yy] ]]; then echo "Continuing!";
else echo "Aborted!"; exit
fi
sleep 3

# if libsodium is built with macports, link it from /opt/local/ to /usr/local
if [ ! -L "/usr/local/lib/libsodium.dylib" ]; then
  # Control will enter here if $DIRECTORY doesn't exist.
   ln -s /opt/local/lib/libsodium.dylib /usr/local/lib/libsodium.dylib
fi
echo "The symlink /usr/local/lib/libsodium.dylib exists."
sleep 3

# replace ppc, i386 as needed.
./configure CC="gcc -arch ppc -arch i386" CXX="g++  -arch ppc -arch i386" CPP="gcc -E" CXXCPP="g++ -E" 

# get rid of prior builds, start clean
make clean
make
echo ""
echo "Sudo is required for make install only, all other steps run without it."
echo "Please type your sudo password below for make install:"
sudo make install

exit
