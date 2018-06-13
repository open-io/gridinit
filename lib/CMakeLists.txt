
include_directories(BEFORE .)

add_library(gridinit-utils STATIC
		uid.c
		common.c
		limits.c
		children.c)

target_link_libraries(gridinit-utils
		${GLIB2_LIBRARIES})
