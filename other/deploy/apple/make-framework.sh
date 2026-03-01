#!/bin/bash
# Make a Tox.xcframework for iOS, iPhone simulator, and macOS from the nightly builds.
#
# Run download-nightly.sh before running this script if you run it locally.

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR"

# Make a Tox.framework for iOS.
rm -rf toxcore-ios/Tox.framework
mkdir -p toxcore-ios/Tox.framework
cp Info.plist toxcore-ios/Tox.framework
cp -r toxcore-ios-arm64/include/tox toxcore-ios/Tox.framework/Headers
lipo -create -output toxcore-ios/Tox.framework/Tox \
  toxcore-ios-arm64/lib/libtoxcore.dylib \
  toxcore-ios-armv7/lib/libtoxcore.dylib \
  toxcore-ios-armv7s/lib/libtoxcore.dylib
install_name_tool -id @rpath/Tox.framework/Tox toxcore-ios/Tox.framework/Tox

# Make a Tox.framework for iPhone simulator.
rm -rf toxcore-iphonesimulator/Tox.framework
mkdir -p toxcore-iphonesimulator/Tox.framework
cp Info.plist toxcore-iphonesimulator/Tox.framework
cp -r toxcore-iphonesimulator-arm64/include/tox toxcore-iphonesimulator/Tox.framework/Headers
lipo -create -output toxcore-iphonesimulator/Tox.framework/Tox \
  toxcore-iphonesimulator-arm64/lib/libtoxcore.dylib \
  toxcore-iphonesimulator-x86_64/lib/libtoxcore.dylib
install_name_tool -id @rpath/Tox.framework/Tox toxcore-iphonesimulator/Tox.framework/Tox

# Make a Tox.framework for macOS.
rm -rf toxcore-macos/Tox.framework
mkdir -p toxcore-macos/Tox.framework
cp Info.plist toxcore-macos/Tox.framework
cp -r toxcore-macos-arm64/include/tox toxcore-macos/Tox.framework/Headers
lipo -create -output toxcore-macos/Tox.framework/Tox \
  toxcore-macos-arm64/lib/libtoxcore.dylib \
  toxcore-macos-x86_64/lib/libtoxcore.dylib
install_name_tool -id @rpath/Tox.framework/Tox toxcore-macos/Tox.framework/Tox

# Make a Tox.xcframework for iOS, iPhone simulator, and macOS.
rm -rf Tox.xcframework
xcodebuild -create-xcframework -output Tox.xcframework \
  -framework toxcore-ios/Tox.framework \
  -framework toxcore-iphonesimulator/Tox.framework \
  -framework toxcore-macos/Tox.framework

# Test the Tox.xcframework.
cat >smoke-test.c <<'EOF'
#include <stdio.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation-deprecated-sync"
#include <tox/tox.h>
#pragma GCC diagnostic pop

int main(void) {
  Tox *tox = tox_new(NULL, NULL);
  if (tox == NULL) {
    fprintf(stderr, "tox_new failed\n");
    return 1;
  }
  tox_kill(tox);
  return 0;
}
EOF
pod lib lint toxcore.podspec

rm smoke-test.c
