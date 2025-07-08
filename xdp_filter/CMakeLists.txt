add_executable(xdp_filter xdp_filter.c maps.c stats.c config.c ip_chain.c)
target_link_libraries(xdp_filter ecbpf json-c)

install(TARGETS xdp_filter RUNTIME DESTINATION bin)

ebpf_program(xdp_filter_kern.c)
