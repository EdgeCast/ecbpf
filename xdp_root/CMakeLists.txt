add_executable(xdp_root_loader xdp_root_loader.c)
target_link_libraries(xdp_root_loader ecbpf json-c)

install(TARGETS xdp_root_loader
        RUNTIME DESTINATION bin)

ebpf_program(xdp_root_kern.c)
ebpf_program(xdp_root_nop_kern.c)
