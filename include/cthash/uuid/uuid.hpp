#ifndef CTHASH_UUID_UUID_HPP
#define CTHASH_UUID_UUID_HPP

#include "utility/conversions.hpp"
#include <array>
#include <iosfwd>
#include <string_view>
#include <cstdint>

namespace cthash {

struct uuid: std::array<std::byte, 16> {
	using super = std::array<std::byte, 16>;
	using super::super;

	struct position_and_size {
		size_t position;
		size_t size;
	};

	static constexpr auto TIME_HIGH = position_and_size{0, 4};
	static constexpr auto TIME_LOW = position_and_size{4, 2};
	static constexpr auto RESERVED = position_and_size{6, 2};
	static constexpr auto FAMILY = position_and_size{8, 1};
	static constexpr auto FAMILY_AND_FIRST_BYTE_OF_NODE = position_and_size{8, 2};
	static constexpr auto NODE = position_and_size{9, 7};
	static constexpr auto REMAINING_OF_NODE = position_and_size{10, 6};

	static constexpr size_t time_low_pos = 4u;
	static constexpr size_t time_low_size = 2u;

	template <position_and_size Info> constexpr auto member() const noexcept {
		return std::span(*this).template subspan<Info.position, Info.size>();
	}

	template <typename CharT, typename Traits> friend auto operator<<(std::basic_ostream<CharT, Traits> & os, const uuid & value) -> std::basic_ostream<CharT, Traits> & {
		constexpr auto hexdec = "0123456789abcdef";

		const auto print = [&os]<std::size_t N>(std::span<const std::byte, N> in) {
			for (std::byte v: in) {
				os << hexdec[unsigned(v) >> 4u] << hexdec[unsigned(v) & 0xFu];
			}
		};

		// time_high
		print(value.member<TIME_HIGH>());
		os << '-';
		// time_low
		print(value.member<TIME_LOW>());
		os << '-';
		// reserved
		print(value.member<RESERVED>());
		os << '-';
		// family
		print(value.member<FAMILY_AND_FIRST_BYTE_OF_NODE>());
		os << '-';
		// node
		print(value.member<REMAINING_OF_NODE>());
		return os;
	}
};

template <typename T> concept uuid_like = requires(const T & in) {
	{ in.time_high() } -> std::same_as<uint32_t>;
	{ in.time_low() } -> std::same_as<uint16_t>;
	{ in.reserved() } -> std::same_as<uint16_t>;
	{ in.family() } -> std::same_as<uint8_t>;
	{ in.node() } -> std::same_as<uint64_t>;
	requires(T().size() == 16);
	requires std::same_as<typename T::value_type, std::byte>;
};

struct uuid_v1: uuid {
	using super = uuid;
	using super::super;

	constexpr auto time_high() const noexcept {
		return utility::big_endian_bytes_to<uint32_t>(super::member<TIME_HIGH>());
	}

	constexpr auto time_low() const noexcept {
		return utility::big_endian_bytes_to<uint16_t>(super::member<TIME_LOW>());
	}

	constexpr auto reserved() const noexcept {
		return utility::big_endian_bytes_to<uint16_t>(super::member<RESERVED>());
	}

	constexpr auto family() const noexcept {
		return utility::big_endian_bytes_to<uint8_t>(super::member<FAMILY>());
	}

	constexpr auto node() const noexcept {
		return utility::big_endian_bytes_to<uint64_t>(super::member<NODE>());
	}
};

struct uuid_v2: uuid {
	using super = uuid;
	using super::super;

	constexpr auto time_high() const noexcept {
		return utility::little_endian_bytes_to<uint32_t>(super::member<TIME_HIGH>());
	}

	constexpr auto time_low() const noexcept {
		return utility::little_endian_bytes_to<uint16_t>(super::member<TIME_LOW>());
	}

	constexpr auto reserved() const noexcept {
		return utility::little_endian_bytes_to<uint16_t>(super::member<RESERVED>());
	}

	constexpr auto family() const noexcept {
		return utility::big_endian_bytes_to<uint8_t>(super::member<FAMILY>());
	}

	constexpr auto node() const noexcept {
		return utility::big_endian_bytes_to<uint64_t>(super::member<NODE>());
	}
};

template <uuid_like T> consteval auto parse(std::string_view input) -> T {
	auto reader_it = input.begin();

	const auto lookahead = [&reader_it, input] -> char {
		if (reader_it == input.end()) {
			throw "unexpected end";
		}

		return *reader_it;
	};

	const auto skip = [&] {
		++reader_it;
	};

	const auto read_one = [&] -> char {
		const char c = lookahead();
		skip();
		return c;
	};

	const auto read_one_if = [&](char expected) {
		if (lookahead() == expected) {
			skip();
			return true;
		} else {
			return false;
		}
	};

	const auto read_and_ensure = [&](char expected) {
		if (lookahead() != expected) {
			throw "unexpected character";
		}
		skip();
	};

	const auto from_hexdec = [](char c) -> int {
		if (c >= '0' && c <= '9') {
			return c - '0';
		} else if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		} else {
			throw "unexpected character in input";
		}
	};

	const auto read_octet = [&] -> std::byte {
		const auto hi = from_hexdec(read_one());
		const auto lo = from_hexdec(read_one());
		return static_cast<std::byte>(hi << 4u | lo);
	};

	auto output = T{};

	// parsing...
	const bool with_braces = read_one_if('{');

	// time_high
	output[0] = read_octet();
	output[1] = read_octet();
	output[2] = read_octet();
	output[3] = read_octet();

	// time_low
	const bool with_dashes = read_one_if('-');
	output[4] = read_octet();
	output[5] = read_octet();

	// reserved
	if (with_dashes) { read_and_ensure('-'); }
	output[6] = read_octet();
	output[7] = read_octet();

	// family
	if (with_dashes) { read_and_ensure('-'); }
	output[8] = read_octet();

	// node
	output[9] = read_octet();
	if (with_dashes) { read_and_ensure('-'); }
	output[10] = read_octet();
	output[11] = read_octet();
	output[12] = read_octet();
	output[13] = read_octet();
	output[14] = read_octet();
	output[15] = read_octet();

	if (with_braces) { read_and_ensure('}'); };

	if (reader_it != input.end()) {
		throw "additional data at end";
	}

	return output;
}

namespace literals {

	consteval auto operator"" _uuid_v1(const char * data, size_t length) {
		return cthash::parse<uuid_v1>(std::string_view(data, length));
	}

	consteval auto operator"" _uuid_v2(const char * data, size_t length) {
		return cthash::parse<uuid_v2>(std::string_view(data, length));
	}

} // namespace literals

} // namespace cthash

#endif
