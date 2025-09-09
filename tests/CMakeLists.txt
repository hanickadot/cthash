if (NOT TARGET Catch2)
find_package(Catch2 3 REQUIRED)
endif()

add_executable(test-runner
	benchmark/sha3-256.cpp
	benchmark/sha512.cpp
	benchmark/sha256.cpp
	sha2/sha512.cpp
	sha2/sha256.cpp
	sha2/sha512t.cpp
	sha2/sha384.cpp
	sha2/sha224.cpp
	sha3/sha3-384.cpp
	sha3/sha3-224.cpp
	sha3/sha3-256.cpp
	sha3/keccak-256.cpp
	sha3/keccak-384.cpp
	sha3/keccak-512.cpp
	sha3/shake256.cpp
	sha3/shake128.cpp
	sha3/sha3-512.cpp
	sha3/xor-overwrite.cpp
	encoding/bit-buffer.cpp
	encoding/base.cpp
	encoding/chunk-of-bits.cpp
	encoding/selection.cpp
	value.cpp
	xxhash/basics.cpp
	keccak.cpp
	hexdec.cpp
)

option(MEASURE_OPENSSL "Measure also OpenSSL" OFF)

if (MEASURE_OPENSSL)
find_package(OpenSSL COMPONENTS Crypto)
if (OpenSSL_FOUND)
target_link_libraries(test-runner PRIVATE OpenSSL::Crypto)
target_compile_definitions(test-runner PRIVATE OPENSSL_BENCHMARK OPENSSL_SUPPRESS_DEPRECATED)
endif()
endif()

target_link_libraries(test-runner PRIVATE Catch2::Catch2WithMain cthash)
target_compile_features(test-runner PUBLIC cxx_std_20)

add_custom_target(test test-runner --skip-benchmarks --colour-mode ansi "" DEPENDS test-runner)
add_custom_target(long-test test-runner --skip-benchmarks --colour-mode ansi "*,[.long]" DEPENDS test-runner)
add_custom_target(benchmark test-runner --colour-mode ansi "" DEPENDS test-runner)


if (CTHASH_COVERAGE)
	coverage_report_after(test test-runner)
endif()