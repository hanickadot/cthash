add_library(cthash INTERFACE)

target_compile_features(cthash INTERFACE cxx_std_23)
target_include_directories(cthash INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_sources(cthash INTERFACE FILE_SET headers TYPE HEADERS FILES
	cthash/cthash.hpp
	cthash/encoding/base.hpp
	cthash/encoding/bit-buffer.hpp
	cthash/encoding/chunk-of-bits.hpp
	cthash/encoding/concepts.hpp
	cthash/encoding/encodings.hpp
	cthash/fixed-string.hpp
	cthash/hasher.hpp
	cthash/simple.hpp
	cthash/value.hpp
	cthash/xxhash.hpp
	cthash/internal/algorithm.hpp
	cthash/internal/bit.hpp
	cthash/internal/concepts.hpp
	cthash/internal/convert.hpp
	cthash/internal/deduce.hpp
	cthash/internal/hexdec.hpp
	cthash/sha2/common.hpp
	cthash/sha2/sha224.hpp
	cthash/sha2/sha256.hpp
	cthash/sha2/sha384.hpp
	cthash/sha2/sha512/t.hpp
	cthash/sha2/sha512.hpp
	cthash/sha3/common.hpp
	cthash/sha3/keccak.hpp
	cthash/sha3/sha3-224.hpp
	cthash/sha3/sha3-256.hpp
	cthash/sha3/sha3-384.hpp
	cthash/sha3/sha3-512.hpp
	cthash/sha3/shake128.hpp
	cthash/sha3/shake256.hpp
)

add_custom_target(single-header DEPENDS single-header.hpp)

add_custom_target(single-header.hpp COMMAND python3 -m quom ${CMAKE_CURRENT_SOURCE_DIR}/cthash/cthash.hpp ${CMAKE_CURRENT_SOURCE_DIR}/cthash-single-header.hpp)
