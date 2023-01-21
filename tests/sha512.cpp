#include <cthash/sha2.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

using namespace cthash::literals;

template <size_t N, typename T = std::byte> consteval auto array_of_zeros() {
	std::array<T, N> output;
	for (T & val: output) val = T{0};
	return output;
}

template <typename Id> struct identify;

TEST_CASE("sha512 zero staging should be empty") {
	const auto block = array_of_zeros<128>();
	const auto staging = cthash::internal_hasher<cthash::sha512_config>::build_staging(block);

	for (auto val: staging) {
		REQUIRE(val == static_cast<decltype(val)>(0));
	}

	STATIC_REQUIRE(cthash::sha512_config::staging_constants[0] == 1);  // ROTR
	STATIC_REQUIRE(cthash::sha512_config::staging_constants[1] == 8);  // ROTR
	STATIC_REQUIRE(cthash::sha512_config::staging_constants[2] == 7);  // SHR
	STATIC_REQUIRE(cthash::sha512_config::staging_constants[3] == 19); // ROTR
	STATIC_REQUIRE(cthash::sha512_config::staging_constants[4] == 61); // ROTR
	STATIC_REQUIRE(cthash::sha512_config::staging_constants[5] == 6);  // SHR

	// REQUIRE((std::same_as<cthash::internal_hasher<cthash::sha512_config>::state_item_t, uint64_t>));
}

TEST_CASE("sha512 resulting buffer (two bytes)") {
	using sha512_hasher = cthash::internal_hasher<cthash::sha512_config>;

	auto h = sha512_hasher{};
	h.update_to_buffer_and_process<std::byte>(std::array<std::byte, 2>{std::byte{'a'}, std::byte{'b'}});
	h.finalize();

	// message
	REQUIRE(unsigned(h.block[0]) == unsigned('a'));
	REQUIRE(unsigned(h.block[1]) == unsigned('b'));

	// terminator
	REQUIRE(unsigned(h.block[2]) == 0b1000'0000u);

	// bit length
	REQUIRE(unsigned(h.block[127]) == 16u); // 2*8 = 16

	STATIC_REQUIRE(h.block.size() == 128zu);

	// rest of the block must be zeros
	for (int i = 0; i != 128; ++i) {
		if (i > 2 && i < 127) {
			REQUIRE(unsigned(h.block[i]) == unsigned{0b0000'0000u});
		}
	}
}

template <size_t N, typename T = std::byte> consteval auto array_of(T value) {
	std::array<T, N> output;
	for (T & val: output) val = value;
	return output;
}

TEST_CASE("sha512 resulting buffer (111B)") {
	using sha512_hasher = cthash::internal_hasher<cthash::sha512_config>;

	auto h = sha512_hasher{};
	h.update_to_buffer_and_process<std::byte>(array_of<111>(std::byte{42}));
	h.finalize();

	// message
	for (int i = 0; i != 111; ++i) {
		REQUIRE(unsigned(h.block[i]) == unsigned(42));
	}

	// terminator
	REQUIRE(unsigned(h.block[111]) == 0b1000'0000u);

	// bit length
	REQUIRE(unsigned(h.block[112]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[113]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[114]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[115]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[116]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[117]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[118]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[119]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[120]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[121]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[122]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[123]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[124]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[125]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[126]) == 0b0000'0011u);
	REQUIRE(unsigned(h.block[127]) == 0b0111'1000u);

	STATIC_REQUIRE(h.block.size() == 128zu);
}

TEST_CASE("sha512 resulting buffer (112B)") {
	using sha512_hasher = cthash::internal_hasher<cthash::sha512_config>;

	auto h = sha512_hasher{};
	h.update_to_buffer_and_process<std::byte>(array_of<112>(std::byte{42}));
	h.finalize();

	// there is no message (as it was in previous block)
	for (int i = 0; i != 112; ++i) {
		REQUIRE(unsigned(h.block[i]) == unsigned(0));
	}

	// bit length
	REQUIRE(unsigned(h.block[112]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[113]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[114]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[115]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[116]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[117]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[118]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[119]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[120]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[121]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[122]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[123]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[124]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[125]) == 0b0000'0000u);
	REQUIRE(unsigned(h.block[126]) == 0b0000'0011u);
	REQUIRE(unsigned(h.block[127]) == 0b1000'0000u);

	STATIC_REQUIRE(h.block.size() == 128zu);
}

TEST_CASE("sha512 empty input") {
	const auto block = [] {
		auto r = array_of_zeros<128>();
		r[0] = std::byte{0b1000'0000};
		return r;
	}();
	const auto staging = cthash::internal_hasher<cthash::sha512_config>::build_staging(block);

	auto it = staging.begin();

	// from the block
	REQUIRE(*it++ == 0x80000000'00000000ull);
	for (int i = 1; i != 16; ++i) {
		REQUIRE(*it++ == 0ull);
	}

	// calculated by staging function
	REQUIRE(staging[16] == 0x80000000'00000000ull);
	REQUIRE(80 == staging.size());

	return;
	// are these correct?
	REQUIRE(staging[17] == 0b00000000000000000000000000000000ul);
	REQUIRE(staging[18] == 0b00000000001000000101000000000000ul);
	REQUIRE(staging[19] == 0b00000000000000000000000000000000ul);
	REQUIRE(staging[20] == 0b00100010000000000000100000000000ul);
	REQUIRE(staging[21] == 0b00000000000000000000000000000000ul);
	REQUIRE(staging[22] == 0b00000101000010001001010101000010ul);
	REQUIRE(staging[23] == 0b10000000000000000000000000000000ul);
	REQUIRE(staging[24] == 0b01011000000010000000000000000000ul);
	REQUIRE(staging[25] == 0b00000000010000001010000000000000ul);
	REQUIRE(staging[26] == 0b00000000000101100010010100000101ul);
	REQUIRE(staging[27] == 0b01100110000000000001100000000000ul);
	REQUIRE(staging[28] == 0b11010110001000100010010110000000ul);
	REQUIRE(staging[29] == 0b00010100001000100101010100001000ul);
	REQUIRE(staging[30] == 0b11010110010001011111100101011100ul);
	REQUIRE(staging[31] == 0b11001001001010000010000000000000ul);
	REQUIRE(staging[32] == 0b11000011111100010000000010010100ul);
	REQUIRE(staging[33] == 0b00101000010011001010011101100110ul);
	REQUIRE(staging[34] == 0b00000110100010000110110111000110ul);
	REQUIRE(staging[35] == 0b10100011011110111111000100010110ul);
	REQUIRE(staging[36] == 0b01110001011111001011111010010110ul);
	REQUIRE(staging[37] == 0b11111110110000101101011101001010ul);
	REQUIRE(staging[38] == 0b10100111101101100111111100000000ul);
	REQUIRE(staging[39] == 0b10000001000101011001011010100010ul);
	REQUIRE(staging[40] == 0b10011000101001101110011101101000ul);
	REQUIRE(staging[41] == 0b00000011101100100000110010000010ul);
	REQUIRE(staging[42] == 0b01011101000111011010011111001001ul);
	REQUIRE(staging[43] == 0b10110001010101101011100100110101ul);
	REQUIRE(staging[44] == 0b11000011110111011100101000010001ul);
	REQUIRE(staging[45] == 0b00100100100111000001000001111111ul);
	REQUIRE(staging[46] == 0b11000100100011010010010011101111ul);
	REQUIRE(staging[47] == 0b01011101111001010100110000110000ul);
	REQUIRE(staging[48] == 0b11011110111111101100111001100101ul);
	REQUIRE(staging[49] == 0b00101100101000010100100000001101ul);
	REQUIRE(staging[50] == 0b00111100000101010011001100101100ul);
	REQUIRE(staging[51] == 0b00000001110011101100100110101101ul);
	REQUIRE(staging[52] == 0b00010110000011001100110011010000ul);
	REQUIRE(staging[53] == 0b00001011101011001101101010011000ul);
	REQUIRE(staging[54] == 0b00110110000110111000111111100000ul);
	REQUIRE(staging[55] == 0b11010010001100100000101110100110ul);
	REQUIRE(staging[56] == 0b00000010100110110111000000000111ul);
	REQUIRE(staging[57] == 0b01110101010001100101100001111100ul);
	REQUIRE(staging[58] == 0b00000111111101010100111100111001ul);
	REQUIRE(staging[59] == 0b11111000000010001101110111000011ul);
	REQUIRE(staging[60] == 0b11011100110010100111011000001000ul);
	REQUIRE(staging[61] == 0b01011110010000100111000110001000ul);
	REQUIRE(staging[62] == 0b01000100101111001110110001011101ul);
	REQUIRE(staging[63] == 0b00111011010111101100010010011011ul);
}

TEST_CASE("sha512 (round 1 for empty message)") {
	const auto block = [] {
		auto r = array_of_zeros<128>();
		r[0] = std::byte{0b1000'0000};
		return r;
	}();
	const auto staging = cthash::internal_hasher<cthash::sha512_config>::build_staging(block);
}

TEST_CASE("sha512 basics", "") {
	constexpr auto v1 = cthash::sha512{}.update("").final();
	REQUIRE(v1 == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"_sha512);

	constexpr auto v2 = cthash::sha512{}.update("hana").final();
	REQUIRE(v2 == "74d15692038cd747dce0f4ff287ce1d5a7930c7e5948183419584f142039b3b25a94d1bf7f321f2fd2da37af1b6552f3e5bfc6c40d0bd8e16ecde338ee153a02"_sha512);

	constexpr auto v3 = cthash::sha512{}.update(array_of_zeros<96>()).final();
	REQUIRE(v3 == "e866b15da9e5b18d4b3bde250fc08a208399440f37471313c5b4006e4151b0f4464b2cd7246899935d58660c0749cd11570bb8240760a6e46bb175be18cdaffe"_sha512);

	constexpr auto v4 = cthash::sha512{}.update(array_of_zeros<120>()).final();
	REQUIRE(v4 == "c106c47ad6eb79cd2290681cb04cb183effbd0b49402151385b2d07be966e2d50bc9db78e00bf30bb567ccdd3a1c7847260c94173ba215a0feabb0edeb643ff0"_sha512);

	constexpr auto v5 = cthash::sha512{}.update(array_of_zeros<128>()).final();
	REQUIRE(v5 == "ab942f526272e456ed68a979f50202905ca903a141ed98443567b11ef0bf25a552d639051a01be58558122c58e3de07d749ee59ded36acf0c55cd91924d6ba11"_sha512);
}
