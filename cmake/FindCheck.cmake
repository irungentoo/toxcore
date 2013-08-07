# - Try to find the CHECK libraries
#  Once done this will define
#
#  CHECK_FOUND - system has check
#  CHECK_INCLUDE_DIR - the check include directory
#  CHECK_LIBRARIES - check library
#  
#  Copyright (c) 2007 Daniel Gollub <dgollub@suse.de>
#  Copyright (c) 2007 Bjoern Ricks  <b.ricks@fh-osnabrueck.de>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.


INCLUDE( FindPkgConfig )

# Take care about check.pc settings
PKG_SEARCH_MODULE( CHECK check )

# Look for CHECK include dir and libraries
IF( NOT CHECK_FOUND )

	FIND_PATH( CHECK_INCLUDE_DIR check.h )

	FIND_LIBRARY( CHECK_LIBRARIES NAMES check )

	IF ( CHECK_INCLUDE_DIR AND CHECK_LIBRARIES )
		SET( CHECK_FOUND 1 )
		IF ( NOT Check_FIND_QUIETLY )
			MESSAGE ( STATUS "Found CHECK: ${CHECK_LIBRARIES}" )
		ENDIF ( NOT Check_FIND_QUIETLY )
	ELSE ( CHECK_INCLUDE_DIR AND CHECK_LIBRARIES )
		IF ( Check_FIND_REQUIRED )
			MESSAGE( FATAL_ERROR "Could NOT find CHECK" )
		ELSE ( Check_FIND_REQUIRED )
			IF ( NOT Check_FIND_QUIETLY )
				MESSAGE( STATUS "Could NOT find CHECK" )	
			ENDIF ( NOT Check_FIND_QUIETLY )
		ENDIF ( Check_FIND_REQUIRED )
	ENDIF ( CHECK_INCLUDE_DIR AND CHECK_LIBRARIES )
ENDIF( NOT CHECK_FOUND )

# Hide advanced variables from CMake GUIs
MARK_AS_ADVANCED( CHECK_INCLUDE_DIR CHECK_LIBRARIES )

