include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# find_package(<package>) call for consumers to find this project
set(package flnav)

install(
    TARGETS flnav
    RUNTIME COMPONENT flnav_Runtime
)

write_basic_package_version_file(
    "${package}ConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)

# Allow package maintainers to freely override the path for the configs
set(
    flnav_INSTALL_CMAKEDIR "${CMAKE_INSTALL_DATADIR}/${package}"
    CACHE PATH "CMake package config location relative to the install prefix"
)
mark_as_advanced(flnav_INSTALL_CMAKEDIR)

install(
    FILES "${PROJECT_BINARY_DIR}/${package}ConfigVersion.cmake"
    DESTINATION "${flnav_INSTALL_CMAKEDIR}"
    COMPONENT flnav_Development
)

# Export variables for the install script to use
install(CODE "
set(flnav_NAME [[$<TARGET_FILE_NAME:flnav>]])
set(flnav_INSTALL_CMAKEDIR [[${flnav_INSTALL_CMAKEDIR}]])
set(CMAKE_INSTALL_BINDIR [[${CMAKE_INSTALL_BINDIR}]])
" COMPONENT flnav_Development)

install(
    SCRIPT cmake/install-script.cmake
    COMPONENT flnav_Development
)

if(PROJECT_IS_TOP_LEVEL)
  include(CPack)
endif()
