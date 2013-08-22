# - Find the curses include file and library
#
#  CURSES_INCLUDE_DIR - the Curses include directory
#  CURSES_LIBRARIES - The libraries needed to use Curses
#  CURSES_HAVE_WIDE_CHAR - true if wide char is available
#  NO_WIDECHAR - Input variable, if set, disable wide char
# ------------------------------------------------------------------------


find_library(CURSES_LIBRARY "curses")
find_library(CURSESW_LIBRARY "cursesw")

find_library(NCURSES_LIBRARY "ncurses")
find_library(NCURSESW_LIBRARY "ncursesw")

if(NOT NO_WIDECHAR AND (CURSESW_LIBRARY OR NCURSESW_LIBRARY))
	message(STATUS "Found wide character support")
	set(CURSES_HAVE_WIDE_CHAR TRUE)
	if(NCURSESW_LIBRARY)
		set(CURSES_LIBRARIES ${NCURSESW_LIBRARY})
	else()
		set(CURSES_LIBRARIES ${CURSESW_LIBRARY})
	endif()
else()
	message(STATUS "Could not found wide character support")
	if(NCURSES_LIBRARY)
		set(CURSES_LIBRARIES ${NCURSES_LIBRARY})
	else()
		set(CURSES_LIBRARIES ${CURSES_LIBRARY})
	endif()
endif()


# We use curses.h not ncurses.h so let's not care about that for now

if(CURSES_HAVE_WIDE_CHAR)
	find_path(CURSES_INCLUDE_PATH curses.h PATH_SUFFIXES ncursesw)
else()
	find_path(CURSES_INCLUDE_PATH curses.h PATH_SUFFIXES ncurses)
endif()

set(CURSES_INCLUDE_DIR ${CURSES_INCLUDE_PATH})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cursesw DEFAULT_MSG CURSES_INCLUDE_DIR CURSES_LIBRARIES)


