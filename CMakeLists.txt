cmake_minimum_required(VERSION 3.0)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_COMPILER "clang") # must come before project

set(VERSION 0.0.1)

if (DEFINED ENV{CI_COMMIT_TAG})
	set(VERSION $ENV{CI_COMMIT_TAG})
endif()

project(ecbpf VERSION ${VERSION})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wimplicit-fallthrough") # Bail on warnings

if (DEFINED ENV{CI_COMMIT_TAG} OR DEFINED ENV{FW_PERF_TEST})
	set(NO_DEBUG 1)
else()
	set(NO_DEBUG 0)
endif()

if(NO_DEBUG)
	string(APPEND CMAKE_C_FLAGS " -DNDEBUG") # Should use add_compile_definitions once on focal
endif()

#
# Sanity check clang/llvm
#
set(LLVM_MINIMUM_VERSION 8)
find_package(LLVM REQUIRED)
if(${LLVM_VERSION_MAJOR} VERSION_LESS ${LLVM_MINIMUM_VERSION})
	message(SEND_ERROR "LLVM version ${LLVM_MINIMUM_VERSION} or greater required.")
endif()

#
# LSB
#
find_program(LSB_RELEASE_EXEC lsb_release)
execute_process(COMMAND ${LSB_RELEASE_EXEC} -cs
    OUTPUT_VARIABLE LSB_RELEASE_CODENAME
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(APPEND CMAKE_C_FLAGS " -D${LSB_RELEASE_CODENAME}") # Should use add_compile_definitions once on focal


#
# External git subtrees
#
set(XDP_SAMPLER_COMMON_SRC "${PROJECT_SOURCE_DIR}/ext/xdp-sampler-common")
set(LIBBPF_SRC "${PROJECT_SOURCE_DIR}/ext/libbpf")

#
# Building libbpf.a
#
set(LIB_BPF_FILE "libbpf.a")
set(LIB_BPF_OBJDIR "${CMAKE_BINARY_DIR}/build_libbpf")
add_custom_command(OUTPUT "${LIB_BPF_FILE}"
				   WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
				   COMMAND make OBJDIR="${LIB_BPF_OBJDIR}" -C "${LIBBPF_SRC}/src" all
				   COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${LIB_BPF_OBJDIR}/${LIB_BPF_FILE}" ${CMAKE_BINARY_DIR}
				)

add_custom_target(libbpf_target DEPENDS "${CMAKE_BINARY_DIR}/${LIB_BPF_FILE}")
add_library(libbpf STATIC IMPORTED)
add_dependencies(libbpf libbpf_target)
set_target_properties(libbpf
    PROPERTIES
    IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/${LIB_BPF_FILE}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_SRC}/include/uapi;${LIBBPF_SRC}/src"
)

#
# Macro for building and install BPF programs
#
set(BPF_PROGRAM_DEST "share/ecbpf/programs")
set(BPF_COMPILE_FLAGS -Wno-compare-distinct-pointer-types -Werror -Wimplicit-fallthrough -D __BPF_TRACING__ -target bpf
					  -D${LSB_RELEASE_CODENAME}
					  -I/usr/include/x86_64-linux-gnu -I${LIBBPF_SRC}/include/uapi
					  -I${LIBBPF_SRC}/src -I${CMAKE_SOURCE_DIR}/libecbpf -O2 -c -g)

if (NO_DEBUG)
	list(APPEND BPF_COMPILE_FLAGS -DNDEBUG)
endif()

macro(ebpf_program)
    set(ebpf_src "${ARGV0}")
    set(ebpf_opts "${ARGV1}")
    string(REPLACE ".c" ".o" ebpf_output "${ebpf_src}")
    string(REPLACE ".c" "" ebpf_target "${ebpf_src}")
    message("Building ${ebpf_src} to ${ebpf_output}")
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_output}"
        COMMAND ${CMAKE_C_COMPILER} ${ebpf_opts} ${BPF_COMPILE_FLAGS} -o "${ebpf_output}" "${ebpf_src}"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${ebpf_output}" "${CMAKE_CURRENT_BINARY_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E remove "${ebpf_output}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        DEPENDS "${ebpf_src}"
        VERBATIM # Otherwise compile flags will be escaped!
    )
    add_custom_target("${ebpf_target}" ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_output}")
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_output}" DESTINATION "${BPF_PROGRAM_DEST}")
    unset(ebpf_src)
    unset(ebpf_opts)
    unset(ebpf_output)
    unset(ebpf_target)
endmacro()

#
# Packaging
#
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS 1) # call ldconfig
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH}~${LSB_RELEASE_CODENAME})
set(CPACK_SYSTEM_NAME amd64) # We could get this from dpkg --print-architecture
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "John Hickey <john.hickey@verizonmedia.com>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "XDP programs and loaders for directors")
set(CPACK_PACKAGE_VENDOR "Verizon Media")
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}_${CPACK_SYSTEM_NAME}")  
if(${LSB_RELEASE_CODENAME} STREQUAL "bionic")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "libelf1,binutils,libczmq4,libprotobuf-c1,lldpd,libjson-c3")
elseif(${LSB_RELEASE_CODENAME} STREQUAL "focal")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "libelf1,binutils,libczmq4,libprotobuf-c1,lldpd,libjson-c4")
elseif(${LSB_RELEASE_CODENAME} STREQUAL "jammy")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "libelf1,binutils,libczmq4,libprotobuf-c1,lldpd,libjson-c5")
else()
	message(SEND_ERROR "Package dependencies not defined for Ubuntu ${LSB_RELEASE_CODENAME}.")
endif()
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/scripts/postinst")
include(CPack) # Must come after setting CPACK variables

#
# Project wide includes and definitions
#
include_directories(libecbpf/)

#
# Subprojects
#
add_subdirectory(libecbpf)
add_subdirectory(xdp_root)
add_subdirectory(xdp_printk)
add_subdirectory(xdp_filter)
add_subdirectory(xdp_sampler)
add_subdirectory(xdp_fw)
add_subdirectory(bypass_ipvs)
add_subdirectory(tests)
add_subdirectory(scripts)
