file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/xdp_bypass_ipvs_common.h" XDP_BYPASS_IPVS_SHA256)

add_executable(xdp_bypass_ipvs xdp_bypass_ipvs_user.c)
target_compile_definitions(xdp_bypass_ipvs PRIVATE XDP_BYPASS_IPVS_COMMON_H_SHA256="${XDP_BYPASS_IPVS_SHA256}")
# We use libbpf below instead of bpf, since that is the target name for libbpf.a.
target_link_libraries(xdp_bypass_ipvs libbpf ecbpf elf z)

# We have a libecbpf version of this program too
# Marc's original elf map modifier
add_executable(elfmapmod elfmapmod.c)
target_link_libraries(elfmapmod elf z)

add_executable(elf_notype_mutator elf_notype_mutator.c)
target_link_libraries(elf_notype_mutator ecbpf)

install(TARGETS xdp_bypass_ipvs
        RUNTIME DESTINATION bin)

ebpf_program(nop_kern.c)
ebpf_program(xdp_bypass_ipvs_tc_kern.c)
ebpf_program(xdp_bypass_ipvs_xdp_kern.c -DXDP_BYPASS_IPVS_COMMON_H_SHA256="${XDP_BYPASS_IPVS_SHA256}")

# Run elfmapmod, see the ebpf_program macro for more context
add_dependencies(xdp_bypass_ipvs_tc_kern elfmapmod)
add_custom_command(TARGET xdp_bypass_ipvs_tc_kern POST_BUILD 
        COMMAND ./elfmapmod xdp_bypass_ipvs_tc_kern.o
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        DEPENDS xdp_bypass_ipvs_tc_kern.o
        COMMENT "Running elfmapmod against xdp_bypass_ipvs_tc_kern.o"
)
add_dependencies(xdp_bypass_ipvs_tc_kern elfmapmod)
add_custom_command(TARGET xdp_bypass_ipvs_xdp_kern POST_BUILD 
        COMMAND ./elfmapmod xdp_bypass_ipvs_xdp_kern.o
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        DEPENDS xdp_bypass_ipvs_xdp_kern.o
        COMMENT "Running elfmapmod against xdp_bypass_ipvs_xdp_kern.o"
)
