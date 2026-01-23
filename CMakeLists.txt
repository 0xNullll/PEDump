cmake_minimum_required(VERSION 3.20)
project(PEDump C)

# Language & standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default to Release if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Source files
set(PEDUMP_SRC
    src/dump/dump_misc.c
    src/dump/dump_pe_flags.c
    src/dump/dump_data_dirs.c
    src/dump/dump_headers.c
    src/dump/dump_raw.c

    src/thirdParty/tiny_regex.c
    src/thirdParty/tiny_sha.c

    src/utils/pe_utils.c
    src/utils/struct_io.c

    src/pe_parser.c
    src/cmds.c
    src/pe_extract.c
    src/main.c
)

add_executable(PEDump ${PEDUMP_SRC})

# Include paths
target_include_directories(PEDump PRIVATE
    src
    src/include
)

# Warnings (kept reasonable)
if (MSVC)
    target_compile_options(PEDump PRIVATE
        /W4
        /permissive-
        /wd4244
        /wd4267
    )

    # Suppress deprecated “unsafe” function warnings
    target_compile_definitions(PEDump PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(PEDump PRIVATE
        -Wall
        -Wextra
        -Wshadow
    )
endif()

# Release optimizations
if (MSVC)
    target_compile_options(PEDump PRIVATE
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/GL>
    )
    target_link_options(PEDump PRIVATE
        $<$<CONFIG:Release>:/LTCG>
    )
else()
    target_compile_options(PEDump PRIVATE
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Release>:-fno-plt>
    )
    target_link_options(PEDump PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:Release>:-s>
    )
endif()

# Link Time Optimization (safe)
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)

if (ipo_supported)
    set_property(TARGET PEDump PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Output directory
set_target_properties(PEDump PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)