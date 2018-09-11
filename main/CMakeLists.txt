include_directories(BEFORE .)

add_executable(gridinit
		uid.c
		common.c
		limits.c
		children.c
		gridinit.c
		utils.c
		cnx.c)
target_link_libraries(gridinit
		${GLIB2_LIBRARIES} ${LIBEVENT_LIBRARIES})

add_executable(gridinit_cmd
		gridinit_cmd.c
		format_output.c
		utils.c
		cnx.c)
target_link_libraries(gridinit_cmd
		${GLIB2_LIBRARIES} ${LIBEVENT_LIBRARIES})

install(TARGETS gridinit gridinit_cmd
		LIBRARY DESTINATION ${LD_LIBDIR}
		PUBLIC_HEADER DESTINATION include
		RUNTIME DESTINATION bin)
