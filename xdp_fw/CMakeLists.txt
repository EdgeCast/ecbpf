find_package(BISON)
find_package(FLEX)

# Make sure we pick up bison generated headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

BISON_TARGET(FwParser parse.y ${CMAKE_CURRENT_BINARY_DIR}/rules_parse.c
			 DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/y.tab.h)
FLEX_TARGET(FwScanner rules_scan.l	${CMAKE_CURRENT_BINARY_DIR}/rules_scan.c)
ADD_FLEX_BISON_DEPENDENCY(FwScanner FwParser)


add_executable(xdp_fw xdp_fw.c rules.c cfg.c test.c hash.c ${BISON_FwParser_OUTPUTS} ${FLEX_FwScanner_OUTPUTS})
target_link_libraries(xdp_fw ecbpf pcap crypto json-c)


ebpf_program(xdp_fw_kern.c)
