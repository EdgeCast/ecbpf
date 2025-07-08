# Make sure we have to protobuf c compiler
find_program(PROTOC protoc-c)
if(NOT PROTOC)
    message(FATAL_ERROR "protoc-c not found. apt install protobuf-c-compiler")
endif()

# We can't use -I because 18.04 protoc-c is broken
add_custom_command(
    OUTPUT  packet_sample.pb-c.c  packet_sample.pb-c.h
    WORKING_DIRECTORY ${XDP_SAMPLER_COMMON_SRC}/protodata/packet_sample
    COMMAND ${PROTOC} --c_out=${CMAKE_CURRENT_BINARY_DIR} packet_sample.proto
)

add_executable(xdp_sampler xdp_sampler.c configuration.c stats.c xzmq.c ${CMAKE_CURRENT_BINARY_DIR}/packet_sample.pb-c.c)
target_include_directories(xdp_sampler PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(xdp_sampler ecbpf libbpf pcap elf z zmq czmq protobuf-c pthread)

add_executable(xdp_sampler_to_pcap xdp_sampler_to_pcap.c ${CMAKE_CURRENT_BINARY_DIR}/packet_sample.pb-c.c)
target_include_directories(xdp_sampler_to_pcap PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(xdp_sampler_to_pcap pcap zmq czmq protobuf-c)

install(TARGETS xdp_sampler xdp_sampler_to_pcap
        RUNTIME DESTINATION bin)