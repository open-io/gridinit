
include_directories(BEFORE .)

add_library(gridinit-utils STATIC
		uid.c
		common.c
		limits.c
		command.c
		children.c
		gridinit-utils.h
		gridinit-internals.h)

target_link_libraries(gridinit-utils
		${GLIB2_LIBRARIES})
