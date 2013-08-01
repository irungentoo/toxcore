# cmake should not fail if sphinx is missing
find_package(Sphinx)

if(SPHINX_EXECUTABLE)
     
    if(NOT DEFINED SPHINX_THEME)
        set(SPHINX_THEME default)
    endif()
     
    if(NOT DEFINED SPHINX_THEME_DIR)
        set(SPHINX_THEME_DIR)
    endif()
     
    # configured documentation tools and intermediate build results
    set(BINARY_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/_build")
     
    # Sphinx cache with pickled ReST documents
    set(SPHINX_CACHE_DIR "${CMAKE_CURRENT_BINARY_DIR}/_doctrees")
     
    # HTML output directory
    set(SPHINX_HTML_DIR "${CMAKE_CURRENT_BINARY_DIR}/html")
     
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/conf.py"
        "${BINARY_BUILD_DIR}/conf.py"
        @ONLY)
     
    add_custom_target(docs
        ${SPHINX_EXECUTABLE}
        -b html
        -c "${BINARY_BUILD_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${SPHINX_HTML_DIR}"
        COMMENT "Building HTML documentation with Sphinx")
else()
    add_custom_target(docs
        echo
        "Please install python-sphinx to build the docs or read the docs online: https://projecttox.readthedocs.org/en/latest"
        COMMENT "No sphinx executebale found")
endif()
