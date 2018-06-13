cmake_minimum_required(VERSION 2.6)
project (GridInit C)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)

set(GridInit_VERSION_MAJOR 1)
set(GridInit_VERSION_MINOR 1)
set(GridInit_RELEASE 5)
set(API_VERSION "${GridInit_VERSION_MAJOR}.${GridInit_VERSION_MINOR}.${GridInit_RELEASE}")
set(SHORT_API_VERSION "${GridInit_VERSION_MAJOR}.${GridInit_VERSION_MINOR}")
if (NOT ABI_VERSION)
	set(ABI_VERSION 0)
endif()

add_definitions(-DAPI_VERSION="${API_VERSION}")
add_definitions(-DSHORT_API_VERSION="${SHORT_API_VERSION}")

set(CMAKE_C_FLAGS "-g -Wall -Wextra -Wunused -pipe -std=gnu99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

if (CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-variadic-macros")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsequence-point")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wredundant-decls")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")

	# gcc >= 4.2
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcomment")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmain")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wparentheses")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfloat-equal")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunsafe-loop-optimizations")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-parameter")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-variable")

	# gcc >= 4.6
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Winline")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-enum")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
MESSAGE("DEBUG symbols enabled")
endif()

set(CMAKE_C_FLAGS_DEBUG          "-O0 -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "-O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -fno-inline")
set(CMAKE_C_FLAGS_MINSIZEREL     "-Os")

add_definitions(-D_REENTRANT)
add_definitions(-D_LARGE_FILES)
add_definitions(-D_LARGEFILE_SOURCE)
add_definitions(-D_LARGEFILE64_SOURCE)
add_definitions(-D_FILE_OFFSET_BITS=64)
add_definitions(-DG_ERRORCHECK_MUTEXES)
add_definitions(-DG_DISABLE_DEPRECATED=1)
add_definitions(-DHAVE_SOCKLEN_T)

if (NOT DEFINED GRIDINIT_SOCK_PATH)
	set(GRIDINIT_SOCK_PATH "/var/run/gridinit.sock")
endif()

add_definitions(-DGRIDINIT_SOCK_PATH="${GRIDINIT_SOCK_PATH}")
MESSAGE("GRIDINIT_SOCK_PATH ${GRIDINIT_SOCK_PATH}")

if (LD_LIBDIR)
	MESSAGE("LD_LIBDIR explicitely set to ${LD_LIBDIR}")
else()
	CHECK_TYPE_SIZE(long SIZEOF_LONG)
	message(STATUS "sizeof(long) = ${SIZEOF_LONG}")
	if(SIZEOF_LONG EQUAL 8)
		set (LD_LIBDIR "lib64")
	else()
		set (LD_LIBDIR "lib")
	endif()
	MESSAGE("LD_LIBDIR guessed to ${LD_LIBDIR}")
endif()


find_package(PkgConfig)
pkg_check_modules(GLIB2 REQUIRED glib-2.0 gthread-2.0 gmodule-2.0)
pkg_check_modules(LIBEVENT REQUIRED libevent)

### explicit plugin directory for alerting modules ###

set(GRIDINIT_PLUGINS_DIRECTORY "${LD_LIBDIR}/gridinit")
if(GRIDINIT_PLUGINS)
	set(GRIDINIT_PLUGINS_DIRECTORY "${GRIDINIT_PLUGINS}")
endif(GRIDINIT_PLUGINS)

set(CMAKE_LIBRARY_PATH "")
set(CMAKE_INCLUDE_PATH "")
include_directories(AFTER ${GLIB2_INCLUDE_DIRS})

add_definitions(-DLOG_DOMAIN="gridinit")
add_definitions(-DGRIDINIT_DOMAIN="gridinit")

add_subdirectory(./lib)
add_subdirectory(./main)

