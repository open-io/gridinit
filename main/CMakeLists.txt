
include_directories(BEFORE .
		../lib)

add_library(gridinit-internals STATIC
		utils.c
		cnx.c
		gridinit_internals.h)
target_link_libraries(gridinit-internals
		${GLIB2_LIBRARIES})

add_executable(gridinit
		gridinit.c
		alerting.c
		gridinit_alerts.h)
target_link_libraries(gridinit
		gridinit-utils gridinit-internals
		${GLIB2_LIBRARIES} ${LIBEVENT_LIBRARIES})
add_executable(gridinit_cmd
		gridinit_cmd.c
		format_output.c)
target_link_libraries(gridinit_cmd
		gridinit-internals
		${GLIB2_LIBRARIES} ${LIBEVENT_LIBRARIES})

add_executable(gridinit_testcmd
		test_cmd.c)
target_link_libraries(gridinit_testcmd
		gridinit-utils gridinit-internals
		${GLIB2_LIBRARIES})

install(TARGETS gridinit gridinit_cmd
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include
		RUNTIME DESTINATION bin)
