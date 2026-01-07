add_executable(bench_single_dfa bench_single_dfa.c)
target_link_libraries(bench_single_dfa PRIVATE zdpi_core)

add_executable(bench_multi_dfa bench_multi_dfa.c)
target_link_libraries(bench_multi_dfa PRIVATE zdpi_core)

add_executable(bench_mfsa bench_mfsa.c)
target_link_libraries(bench_mfsa PRIVATE zdpi_core)

add_executable(bench_stress bench_stress.c)
target_link_libraries(bench_stress PRIVATE zdpi_core)

add_executable(bench_fuzz bench_fuzz.c)
target_link_libraries(bench_fuzz PRIVATE zdpi_core)

add_executable(bench_pcap bench_pcap.c)
target_link_libraries(bench_pcap PRIVATE zdpi_core)

add_executable(bench_large_scale bench_large_scale.c)
target_link_libraries(bench_large_scale PRIVATE zdpi_core)

add_executable(bench_arena_stress bench_arena_stress.c)
target_link_libraries(bench_arena_stress PRIVATE zdpi_core)

add_executable(bench_arena_throughput bench_arena_throughput.c)
target_link_libraries(bench_arena_throughput PRIVATE zdpi_core)

add_executable(bench_real_rules bench_real_rules.c)
target_link_libraries(bench_real_rules PRIVATE zdpi_core)
