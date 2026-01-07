add_library(zdpi_core STATIC
	src/rule_parser.c
	src/regex_parser.c
	src/nfa.c
	src/dfa.c
	src/ec_compress.c
	src/linearize.c
	src/arena_flash.c
	src/mfsa.c
	src/ac.c
	src/zdpi_log.c
)
target_include_directories(zdpi_core PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/src/common
	${PROJECT_SOURCE_DIR}/include
	${LIBBPF_INCLUDE_DIRS}
	${LIBPCRE2_INCLUDE_DIRS}
)
target_link_libraries(zdpi_core PUBLIC
	zdpi_skel
	${LIBBPF_LIBRARIES}
	${LIBPCRE2_LIBRARIES}
	-lelf -lz
)
add_dependencies(zdpi_core zdpi_bpf_skel)

add_executable(zdpi-cli src/main.c)
target_link_libraries(zdpi-cli PRIVATE zdpi_core)
