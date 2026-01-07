cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(zdpi VERSION 0.0.1 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Werror -Wextra -Wno-unused-parameter)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	message(STATUS "Building in Debug mode")
	add_compile_options(-g -O0 -Wpedantic)
	add_definitions(-DDEBUG)
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
	message(STATUS "Building in Release mode")
	add_compile_options(-O3)
	add_definitions(-DNDEBUG)
endif()

add_compile_definitions(
	ZDPI_VERSION_MAJOR="${PROJECT_VERSION_MAJOR}"
	ZDPI_VERSION_MINOR="${PROJECT_VERSION_MINOR}"
	ZDPI_VERSION_PATCH="${PROJECT_VERSION_PATCH}"
	ZDPI_VERSION="${PROJECT_VERSION}"
)

# Tunable limits override via cmake -DZDPI_MAX_STATES=65536 etc.
set(ZDPI_MAX_STATES "" CACHE STRING "Max DFA states (default: 1048576)")
set(ZDPI_MAX_RULES "" CACHE STRING "Max rules (default: 131072)")
set(ZDPI_MAX_PAYLOAD "" CACHE STRING "Max payload bytes (default: 1500)")
set(ZDPI_ARENA_PAGES "" CACHE STRING "Arena pages (default: 262144)")
set(NFA_DEFAULT_CAPACITY "" CACHE STRING "NFA default capacity (default: 8192)")

if (ZDPI_MAX_STATES)
	add_compile_definitions(ZDPI_MAX_STATES=${ZDPI_MAX_STATES})
endif()
if (ZDPI_MAX_RULES)
	add_compile_definitions(ZDPI_MAX_RULES=${ZDPI_MAX_RULES})
endif()
if (ZDPI_MAX_PAYLOAD)
	add_compile_definitions(ZDPI_MAX_PAYLOAD=${ZDPI_MAX_PAYLOAD})
endif()
if (ZDPI_ARENA_PAGES)
	add_compile_definitions(ZDPI_ARENA_PAGES=${ZDPI_ARENA_PAGES})
endif()
if (NFA_DEFAULT_CAPACITY)
	add_compile_definitions(NFA_DEFAULT_CAPACITY=${NFA_DEFAULT_CAPACITY})
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf>=1.4)
pkg_check_modules(LIBPCRE2 REQUIRED libpcre2-8)

set(BPF_CLANG clang CACHE STRING "Clang compiler for BPF")
set(BPFTOOL bpftool CACHE STRING "bpftool binary")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

add_subdirectory(src/dataplane)
add_subdirectory(src/control)

option(BUILD_TESTS "Build test suite" ON)
if (BUILD_TESTS)
	enable_testing()
	find_package(GTest REQUIRED)
	add_subdirectory(tests)
endif()

option(BUILD_BENCHMARKS "Build benchmarking suite" OFF)
if (BUILD_BENCHMARKS)
	add_subdirectory(perf_tests)
endif()
