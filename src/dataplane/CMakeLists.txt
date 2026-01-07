set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/zdpi_kern.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/zdpi_kern.bpf.o)
set(BPF_SKEL ${CMAKE_CURRENT_BINARY_DIR}/zdpi_kern.skel.h)

add_custom_command(OUTPUT ${BPF_OBJ}
	COMMAND ${BPF_CLANG} -g -O2 --target=bpf
		-D__TARGET_ARCH_x86
		-D__BPF_FEATURE_ADDR_SPACE_CAST
		-I${PROJECT_SOURCE_DIR}/include
		-I${PROJECT_SOURCE_DIR}/src/common
		-c ${BPF_SRC} -o ${BPF_OBJ}
	DEPENDS ${BPF_SRC}
		${PROJECT_SOURCE_DIR}/src/common/zdpi_types.h
		${PROJECT_SOURCE_DIR}/src/common/zdpi_defs.h
	COMMENT "Compiling BPF object: zdpi_kern.bpf.c"
	VERBATIM)

add_custom_command(OUTPUT ${BPF_SKEL}
	COMMAND ${BPFTOOL} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
	DEPENDS ${BPF_OBJ}
	COMMENT "Generating BPF skeleton: zdpi_kern.skel.h"
	VERBATIM)

add_custom_target(zdpi_bpf_skel DEPENDS ${BPF_SKEL})

add_library(zdpi_skel INTERFACE)
add_dependencies(zdpi_skel zdpi_bpf_skel)
target_include_directories(zdpi_skel INTERFACE ${CMAKE_CURRENT_BINARY_DIR})
