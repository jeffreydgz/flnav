cmake_minimum_required(VERSION 3.14)

include(cmake/prelude.cmake)

set(CMAKE_CXX_STANDARD 17)
project(
        flnav
        VERSION 1.0.6
        DESCRIPTION "An enhanced log file viewer for forensic triage."
        HOMEPAGE_URL "https://github.com/jeffreydgz/flnav"
        LANGUAGES CXX C
)

include(cmake/project-is-top-level.cmake)
include(cmake/variables.cmake)

find_package(PkgConfig REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(BZip2 REQUIRED)
find_package(LibArchive REQUIRED)
find_package(ZLIB REQUIRED)
find_package(pcre2 CONFIG REQUIRED)
find_package(CURL REQUIRED)

set(lnav_LIBS
        CURL::libcurl
        unofficial::sqlite3::sqlite3
        BZip2::BZip2
        PCRE2::8BIT PCRE2::16BIT PCRE2::32BIT PCRE2::POSIX
        LibArchive::LibArchive
        ZLIB::ZLIB
        ${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib/libunistring.a
)

add_subdirectory(src)
add_subdirectory(test)

# ---- Install rules ----

if (NOT CMAKE_SKIP_INSTALL_RULES)
    include(cmake/install-rules.cmake)
endif ()

# ---- Developer mode ----

if (NOT flnav_DEVELOPER_MODE)
    return()
elseif (NOT PROJECT_IS_TOP_LEVEL)
    message(
            AUTHOR_WARNING
            "Developer mode is intended for developers of flnav"
    )
endif ()

include(cmake/dev-mode.cmake)
