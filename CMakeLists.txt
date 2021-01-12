cmake_minimum_required(VERSION 2.8)
project (GridInit C)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)

# These variables cannot be set from CLI
set(GridInit_VERSION_MAJOR 2)
set(GridInit_VERSION_MINOR 2)
set(GridInit_RELEASE 0)
# This variable can be set from CLI: cmake -DAPI_VERSION=1.2.3 [...]
set(API_VERSION "${GridInit_VERSION_MAJOR}.${GridInit_VERSION_MINOR}.${GridInit_RELEASE}" CACHE STRING "Gridinit full version number")

add_definitions(-DAPI_VERSION="${API_VERSION}")
add_definitions(-DSHORT_API_VERSION="${SHORT_API_VERSION}")

option(ASAN "Enable ASAN (address sanitizer)" OFF)
option(TSAN "Enable TSAN (thread sanitizer)" OFF)
option(FSAN "Enable FSAN (frames sanitizer)" OFF)

set(SAN_CFLAGS "")
if (ASAN)
	set(SAN_CFLAGS "-fno-omit-frame-pointer -fsanitize=address")
endif ()
if (TSAN)
	set(SAN_CFLAGS "-fno-omit-frame-pointer -fsanitize=thread")
endif ()
if (FRAMES)
	set(SAN_CFLAGS "${SAN_CFLAGS} -fstack-protector-all")
endif ()

set(CMAKE_C_FLAGS "-Wall -Wextra -Wunused -pipe -std=gnu99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-variadic-macros")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsequence-point")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wredundant-decls")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")

	# gcc >= 4.2
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcomment")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmain")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wparentheses")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfloat-equal")

	# gcc >= 4.6
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Winline")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wconversion")
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-enum")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-parameter")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-variable")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-macros")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-value")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-function")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-result")

	if (CMAKE_COMPILER_IS_GNUCC)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wtrampolines")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunsafe-loop-optimizations")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-parameter")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-but-set-variable")
	endif()
else()
	message("The default compiler set in CC is not supported.")
	message("You need to use gcc (with a version >= 4.2) or Clang (version >= 9)")
	message("You can set your default compiler either by updating your CC variable environment:")
	message("export CC=/path/to/gcc")
	message("export CC=/path/to/clang-9")
	message("Or by adding a flag when calling CMake: ")
	message("-D CMAKE_C_COMPILER=gcc")
	message("-D CMAKE_C_COMPILER=clang-9")
	message( FATAL_ERROR "CMake will exit.")
endif()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SAN_CFLAGS}")

if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
MESSAGE("DEBUG symbols enabled")
endif()

set(CMAKE_C_FLAGS_DEBUG          "-g -O0 -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "-g -O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -O2")
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
endif()


find_package(PkgConfig)
pkg_check_modules(GLIB2 REQUIRED glib-2.0 gthread-2.0 gmodule-2.0)
pkg_check_modules(DILL REQUIRED libdill)

include_directories(AFTER
	${DILL_INCLUDE_DIRS}
	${GLIB2_INCLUDE_DIRS})

link_directories(
	${DILL_LIBRARY_DIRS}
	${GLIB2_LIBRARY_DIRS})

include_directories(BEFORE
	${CMAKE_SOURCE_DIR}/main)

add_definitions(-DLOG_DOMAIN="gridinit")

add_executable(gridinit
		main/gridinit.c
		main/children.c
		main/limits.c
		main/uid.c
		main/utils.c)
target_link_libraries(gridinit ${GLIB2_LIBRARIES} ${DILL_LIBRARIES})


add_executable(gridinit_cmd
		main/gridinit_cmd.c
		main/utils.c)
target_link_libraries(gridinit_cmd ${GLIB2_LIBRARIES})

install(TARGETS gridinit gridinit_cmd
		RUNTIME DESTINATION bin)
