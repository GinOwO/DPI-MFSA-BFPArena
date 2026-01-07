add_executable(zdpi_tests
	src/bootstrap_test.cpp
	src/test_regex_parser.cpp
	src/test_nfa.cpp
	src/test_dfa.cpp
	src/test_ec_compress.cpp
	src/test_linearize.cpp
	src/test_mfsa.cpp
	src/test_e2e.cpp
	src/test_ac.cpp
)
target_include_directories(zdpi_tests PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${PROJECT_SOURCE_DIR}/src/control/include
	${PROJECT_SOURCE_DIR}/src/common
)
target_compile_definitions(zdpi_tests PRIVATE
	ZDPI_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(zdpi_tests PRIVATE
	zdpi_core
	GTest::GTest
	GTest::Main
)
gtest_discover_tests(zdpi_tests)
