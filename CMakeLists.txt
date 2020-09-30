cmake_minimum_required(VERSION 2.8)
project (GridInit C)

include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckTypeSize)

set(GridInit_VERSION_MAJOR 2)
set(GridInit_VERSION_MINOR 0)
set(GridInit_RELEASE 2)
set(API_VERSION "${GridInit_VERSION_MAJOR}.${GridInit_VERSION_MINOR}.${GridInit_RELEASE}")
set(SHORT_API_VERSION "${GridInit_VERSION_MAJOR}.${GridInit_VERSION_MINOR}")

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

set(CMAKE_C_FLAGS "-g -Wall -Wextra -Wunused -pipe -std=gnu99")
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
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused-const-variable")
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

set(CMAKE_C_FLAGS_DEBUG          "-Og -fno-inline")
set(CMAKE_C_FLAGS_RELEASE        "-O2")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2")
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

add_custom_target(
	libdill_s
	ALL
	COMMAND ./autogen.sh
	COMMAND ./configure --enable-static --disable-shared
	COMMAND make
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/vendor/sustrik/libdill
	COMMENT "Building libdill")

if (NOT (${CMAKE_BINARY_DIR} STREQUAL ${CMAKE_SOURCE_DIR}))
add_custom_target(
	libdill_source
	ALL
	COMMAND mkdir -p ${CMAKE_BINARY_DIR}/vendor/sustrik/libdill
	COMMAND cd ${CMAKE_BINARY_DIR}/vendor/sustrik/libdill && lndir ${CMAKE_SOURCE_DIR}/vendor/sustrik/libdill
	COMMENT "Preparing the source of libdill")
	add_dependencies(libdill_s libdill_source)
endif()

set(CMAKE_LIBRARY_PATH "")
set(CMAKE_INCLUDE_PATH "")
include_directories(AFTER
	${CMAKE_SOURCE_DIR}/vendor/sustrik/libdill
	${GLIB2_INCLUDE_DIRS})

add_definitions(-DLOG_DOMAIN="gridinit")

include_directories(BEFORE ${CMAKE_SOURCE_DIR}/main)

add_executable(gridinit
		main/gridinit.c
		main/children.c
		main/limits.c
		main/uid.c
		main/utils.c)
target_link_libraries(gridinit
		${GLIB2_LIBRARIES}
		${CMAKE_BINARY_DIR}/vendor/sustrik/libdill/.libs/libdill.a
		-pthread -lrt)
add_dependencies(gridinit
		libdill_s)


add_executable(gridinit_cmd
		main/gridinit_cmd.c
		main/utils.c)
target_link_libraries(gridinit_cmd ${GLIB2_LIBRARIES})

install(TARGETS gridinit gridinit_cmd
		RUNTIME DESTINATION bin)
