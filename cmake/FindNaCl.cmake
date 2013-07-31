find_path(NACL_INCLUDE_DIR crypto_box.h
	$ENV{NACL_INCLUDE_DIR} /usr/include/nacl/
	DOC "Directory which contain NaCl headers")

find_path(NACL_LIBRARY_DIR libnacl.a
	$ENV{NACL_LIBRARY_DIR} /usr/lib/nacl
	DOC "Directory which contain libnacl.a, cpucycles.o, and randombytes.o")

if(NACL_LIBRARY_DIR)
	set(NACL_LIBRARIES
		"${NACL_LIBRARY_DIR}/cpucycles.o"
		"${NACL_LIBRARY_DIR}/libnacl.a"
		"${NACL_LIBRARY_DIR}/randombytes.o")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NaCl DEFAULT_MSG NACL_INCLUDE_DIR NACL_LIBRARY_DIR NACL_LIBRARIES)
