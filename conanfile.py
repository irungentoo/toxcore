# pylint: disable=not-callable
import os
import re

from conans import CMake
from conans import ConanFile
from conans.tools import collect_libs
from conans.tools import load


class ToxConan(ConanFile):
    name = "c-toxcore"
    url = "https://tox.chat"
    description = "The future of online communications."
    license = "GPL-3.0-only"
    settings = "os", "compiler", "build_type", "arch"
    requires = "libsodium/1.0.18", "opus/1.3.1", "libvpx/1.9.0"
    generators = "cmake_find_package"
    scm = {"type": "git", "url": "auto", "revision": "auto"}

    options = {"with_tests": [True, False]}
    default_options = {"with_tests": False}

    _cmake = None

    def _create_cmake(self):
        if self._cmake is not None:
            return self._cmake

        self._cmake = CMake(self)
        self._cmake.definitions["AUTOTEST"] = self.options.with_tests
        self._cmake.definitions["BUILD_MISC_TESTS"] = self.options.with_tests
        self._cmake.definitions["MUST_BUILD_TOXAV"] = True
        if self.settings.compiler == "Visual Studio":
            self._cmake.definitions["MSVC_STATIC_SODIUM"] = True

        self._cmake.configure()
        return self._cmake

    def set_version(self):
        content = load(os.path.join(self.recipe_folder, "CMakeLists.txt"))
        version_major = re.search(r"set\(PROJECT_VERSION_MAJOR \"(.*)\"\)",
                                  content).group(1)
        version_minor = re.search(r"set\(PROJECT_VERSION_MINOR \"(.*)\"\)",
                                  content).group(1)
        version_patch = re.search(r"set\(PROJECT_VERSION_PATCH \"(.*)\"\)",
                                  content).group(1)
        self.version = "%s.%s.%s" % (
            version_major.strip(),
            version_minor.strip(),
            version_patch.strip(),
        )

    def requirements(self):
        if self.settings.os == "Windows":
            self.requires("pthreads4w/3.0.0")

    def build(self):
        cmake = self._create_cmake()
        cmake.build()

        if self.options.with_tests:
            cmake.test()

    def package(self):
        cmake = self._create_cmake()
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = collect_libs(self)

        if self.settings.os == "Windows":
            self.cpp_info.system_libs = ["Ws2_32", "Iphlpapi"]
