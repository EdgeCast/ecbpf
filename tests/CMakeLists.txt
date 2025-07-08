add_executable(test_xdp_root test_xdp_root.c)
target_include_directories(test_xdp_root PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/libecbpf> $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/libbpf/include> $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/libbpf/src>)
target_link_libraries(test_xdp_root libbpf ecbpf)

file(COPY stats.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS test_xdp_root
        RUNTIME DESTINATION bin)
