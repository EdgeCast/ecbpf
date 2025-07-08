configure_file(libecbpf_config.h.in libecbpf_config.h @ONLY)

add_library(ecbpf STATIC libecbpf.c libecbpf_elf.c libecbpf.h xdp_stats.h)
target_link_libraries(ecbpf libbpf elf z)
target_include_directories(ecbpf PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
