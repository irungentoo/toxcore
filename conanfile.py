# pylint: disable=not-callable
from conans import CMake
from conans import ConanFile


class ToxConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    requires = "libsodium/1.0.18", "opus/1.3.1", "libvpx/1.8.0@bincrafters/stable"
    generators = "cmake_find_package"

    def requirements(self):
        if self.settings.os == "Windows":
            self.requires("pthreads4w/3.0.0")

    def source(self):
        self.run("git clone https://github.com/toktok/c-toxcore.git")

    def build(self):
        cmake = CMake(self)
        cmake.definitions["AUTOTEST"] = True
        cmake.definitions["BUILD_MISC_TESTS"] = True
        cmake.definitions["MUST_BUILD_TOXAV"] = True
        if self.settings.compiler == "Visual Studio":
            cmake.definitions["MSVC_STATIC_SODIUM"] = True

        if self.should_configure:
            cmake.configure()

        if self.should_build:
            cmake.build()

        if self.should_test:
            cmake.test()
