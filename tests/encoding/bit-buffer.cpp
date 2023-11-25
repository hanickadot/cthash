#include <catch2/catch_test_macros.hpp>
#include <cthash/encoding/bit-buffer.hpp>

using namespace std::string_view_literals;

TEST_CASE("bit_buffer(1)") {
	auto buffer = cthash::bit_buffer<6, 8>{};
	REQUIRE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());
	buffer.push(0xFFu);
	REQUIRE(!buffer.empty());
	REQUIRE(buffer.has_bits_for_pop());
	REQUIRE(buffer.size() == 1u);

	const auto out1 = buffer.front();
	buffer.pop();
	REQUIRE(out1 == 0b111111u);
}

TEST_CASE("bit_buffer(2)") {
	auto buffer = cthash::bit_buffer<6, 8>{};
	REQUIRE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());

	buffer.push(0xFFu);
	REQUIRE(buffer.size() == 1u);

	REQUIRE(buffer.has_bits_for_pop());
	REQUIRE_FALSE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());
	buffer.push(0xFFu);
	REQUIRE(buffer.size() == 2u);

	REQUIRE(buffer.has_bits_for_pop());
	REQUIRE_FALSE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());
	buffer.push(0xFFu);
	REQUIRE(buffer.size() == 4u);

	REQUIRE(buffer.has_bits_for_pop());
	REQUIRE_FALSE(buffer.empty());
	REQUIRE_FALSE(buffer.has_capacity_for_push());

	const auto out1 = buffer.front();
	buffer.pop();
	REQUIRE(out1 == 0b111111u);

	const auto out2 = buffer.front();
	buffer.pop();
	REQUIRE(out2 == 0b111111u);

	const auto out3 = buffer.front();
	buffer.pop();
	REQUIRE(out3 == 0b111111u);

	const auto out4 = buffer.front();
	buffer.pop();
	REQUIRE(out4 == 0b111111u);

	REQUIRE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());
	REQUIRE_FALSE(buffer.has_bits_for_pop());
}

TEST_CASE("bit_buffer(3) check patterns") {
	auto buffer = cthash::bit_buffer<6, 8>{};
	REQUIRE(buffer.capacity() == 24); // bits

	REQUIRE(buffer.empty());
	REQUIRE(buffer.has_capacity_for_push());
	REQUIRE(buffer.size() == 0u);
	REQUIRE(buffer.unused_size() == 3u);

	REQUIRE_FALSE(buffer.full());

	buffer.push(0x86u);
	REQUIRE(buffer.unused_size() == 2u);
	REQUIRE(buffer.size() == 1u);
	REQUIRE(buffer.has_capacity_for_push());

	buffer.push(0x18u);
	REQUIRE(buffer.unused_size() == 1u);
	REQUIRE(buffer.size() == 2u);
	REQUIRE(buffer.has_capacity_for_push());

	buffer.push(0x61u);
	REQUIRE(buffer.unused_size() == 0u);
	REQUIRE(buffer.size() == 4u);

	REQUIRE_FALSE(buffer.empty());
	REQUIRE_FALSE(buffer.has_capacity_for_push());
	REQUIRE(buffer.full());

	auto front_and_pop = [&] {
		REQUIRE_FALSE(buffer.empty());
		const auto out1 = buffer.front();
		buffer.pop();
		return out1;
	};

	REQUIRE(front_and_pop() == 0b100001u);
	REQUIRE(front_and_pop() == 0b100001u);
	REQUIRE(front_and_pop() == 0b100001u);
	REQUIRE(front_and_pop() == 0b100001u);

	REQUIRE(buffer.empty());
}

TEST_CASE("calculating capacity for typical BASE-n") {
	const auto base2 = cthash::bit_buffer<1>{};
	REQUIRE(base2.capacity() == 8u);
	REQUIRE(base2.in_capacity() == 1u);
	REQUIRE(base2.out_capacity() == 8u);

	const auto base4 = cthash::bit_buffer<2>{};
	REQUIRE(base4.capacity() == 8u);
	REQUIRE(base4.in_capacity() == 1u);
	REQUIRE(base4.out_capacity() == 4u);

	const auto base8 = cthash::bit_buffer<3>{};
	REQUIRE(base8.capacity() == 24u);
	REQUIRE(base8.in_capacity() == 3u);
	REQUIRE(base8.out_capacity() == 8u);

	const auto base16 = cthash::bit_buffer<4>{};
	REQUIRE(base16.capacity() == 8u);
	REQUIRE(base16.in_capacity() == 1u);
	REQUIRE(base16.out_capacity() == 2u);

	const auto base32 = cthash::bit_buffer<5>{};
	REQUIRE(base32.capacity() == 40u);
	REQUIRE(base32.in_capacity() == 5u);
	REQUIRE(base32.out_capacity() == 8u);

	const auto base64 = cthash::bit_buffer<6>{};
	REQUIRE(base64.capacity() == 24u);
	REQUIRE(base64.in_capacity() == 3u);
	REQUIRE(base64.out_capacity() == 4u);

	const auto base128 = cthash::bit_buffer<7>{};
	REQUIRE(base128.capacity() == 56u);
	REQUIRE(base128.in_capacity() == 7u);
	REQUIRE(base128.out_capacity() == 8u);

	const auto base256 = cthash::bit_buffer<8>{};
	REQUIRE(base256.capacity() == 8u);
	REQUIRE(base256.in_capacity() == 1u);
	REQUIRE(base256.out_capacity() == 1u);
}

TEST_CASE("calculate padding for base64") {
	REQUIRE(cthash::calculate_padding_bit_count(0, 6, 8) == 0);
	REQUIRE(cthash::calculate_padding_bit_count(2, 6, 8) == 16);
	REQUIRE(cthash::calculate_padding_bit_count(4, 6, 8) == 8);
}
