file(
    RELATIVE_PATH relative_path
    "/${flnav_INSTALL_CMAKEDIR}"
    "/${CMAKE_INSTALL_BINDIR}/${flnav_NAME}"
)

get_filename_component(prefix "${CMAKE_INSTALL_PREFIX}" ABSOLUTE)
set(config_dir "${prefix}/${flnav_INSTALL_CMAKEDIR}")
set(config_file "${config_dir}/flnavConfig.cmake")

message(STATUS "Installing: ${config_file}")
file(WRITE "${config_file}" "\
set(
    FLNAV_EXECUTABLE
    \"\${CMAKE_CURRENT_LIST_DIR}/${relative_path}\"
    CACHE FILEPATH \"Path to the flnav executable\"
)
")
