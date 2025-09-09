#ifndef CTHASH_ENCODING_ENCODINGS_HPP
#define CTHASH_ENCODING_ENCODINGS_HPP

#include "concepts.hpp"
#include <optional>
#include <variant>

namespace cthash {

namespace encoding {

	template <typename...> struct list { };

	struct base64 {
		static constexpr std::string_view name = "base64";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		static constexpr char padding = '=';
	};

	struct base64_no_padding {
		static constexpr std::string_view name = "base64_no_padding";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	};

	struct base64url {
		static constexpr std::string_view name = "base64url";
		static constexpr std::string_view alt_name = "base64_url";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	};

	static_assert(padded_encoding<base64>);

	struct base32 {
		static constexpr std::string_view name = "base32";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		static constexpr char padding = '=';
	};

	struct base32_no_padding {
		static constexpr std::string_view name = "base32_no_padding";

		static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	};

	struct z_base32 {
		static constexpr std::string_view name = "z_base32";
		static constexpr std::string_view alt_name = "zbase32";

		static constexpr char alphabet[] = "ybndrfg8ejkmcpqxot1uwisza345h769";
	};

	struct base16 {
		static constexpr std::string_view name = "base16";
		static constexpr std::string_view alt_name = "hexdec";

		static constexpr char alphabet[] = "0123456789abcdef";
	};

	using hexdec = base16;

	struct base16_uppercase {
		static constexpr std::string_view name = "BASE16";
		static constexpr std::string_view alt_name = "HEXDEC";

		static constexpr char alphabet[] = "0123456789ABCDEF";
	};

	using hexdec_uppercase = base16_uppercase;

	struct base8 {
		static constexpr std::string_view name = "base8";
		static constexpr std::string_view alt_name = "octal";

		static constexpr char alphabet[] = "01234567";
		static constexpr char padding = '=';
	};

	using octal = base8;

	struct base4 {
		static constexpr std::string_view name = "base4";

		static constexpr char alphabet[] = "0123";
	};

	struct base2 {
		static constexpr std::string_view name = "base2";
		static constexpr std::string_view alt_name = "binary";

		static constexpr char alphabet[] = "01";
	};

	using binary = base2;

	using known_encodings = list<base64, base64_no_padding, base64url, base32, base32_no_padding, z_base32, base16, base16_uppercase, base8, base4, base2>;

} // namespace encoding

template <typename Defs> struct dynamic_encodings;

template <typename Encoding> concept has_alt_name = requires {
	{ Encoding::alt_name } -> std::same_as<const std::string_view &>;
};

static_assert(has_alt_name<encoding::hexdec>);

template <typename T, typename... Ts> concept one_from = (std::same_as<T, Ts> || ... || false);

template <typename Encoding> constexpr size_t longest_name_for = Encoding::name.size();
template <has_alt_name Encoding> constexpr size_t longest_name_for<Encoding> = std::max(Encoding::name.size(), Encoding::alt_name.size());

template <typename Encoding> constexpr bool match_encoding(std::string_view name) noexcept {
	return Encoding::name == name;
}

template <has_alt_name Encoding> constexpr bool match_encoding(std::string_view name) noexcept {
	return Encoding::name == name || Encoding::alt_name == name;
}

template <typename... List> struct dynamic_encodings<encoding::list<List...>>: std::variant<List...> {
	using super = std::variant<List...>;

	template <typename Encoding> static constexpr bool assign_encoding(std::string_view name, std::optional<super> & output) noexcept {
		auto r = match_encoding<Encoding>(name);

		if (!r) {
			return false;
		}

		output = Encoding{};
		return true;
	}

	static constexpr auto select_encoding(std::string_view name) -> super {
		std::optional<super> output{std::nullopt};

		// I'm not using bool to avoid warning to have better code coverage
		const auto success = (unsigned(assign_encoding<List>(name, output)) | ... | 0u);

		if (!success) {
			throw std::invalid_argument{"unknown encoding name"};
		}

		assert(output.has_value());

		return *output;
	}

	static constexpr size_t longest_name_size = std::max({longest_name_for<List>...});

	constexpr dynamic_encodings(std::string_view name): super(select_encoding(name)) { }
	constexpr dynamic_encodings(one_from<List...> auto enc) noexcept: super(enc) { }

	template <typename Fnc> constexpr auto visit(Fnc && fnc) const {
		return std::visit(std::forward<Fnc>(fnc), static_cast<const super &>(*this));
	}
};

template <typename Encoding, typename DefaultEncoding = encoding::hexdec, typename InputContext> constexpr auto select_encoding(InputContext && input) {
	using iterator_t = decltype(std::ranges::begin(input));

	struct result {
		Encoding encoding;
		iterator_t iterator;
	};

	auto it = std::ranges::begin(input);

	if (it == std::ranges::end(input) || *it == '}') {
		return result{.encoding = DefaultEncoding{}, .iterator = it};
	}

	// this will copy it into buffer to compare
	std::array<char, Encoding::longest_name_size> buffer{};
	auto out = buffer.begin();

	for (;;) {
		if (it == std::ranges::end(input)) {
			break;
		}

		const char c = *it;

		if (c == '}') {
			break;
		}

		if (out != buffer.end()) {
			*out++ = c;
		}

		++it;
	}

	const std::string_view name = std::string_view(buffer.data(), static_cast<size_t>(std::distance(buffer.begin(), out)));

	return result{.encoding = Encoding(name), .iterator = it};
}

using runtime_encoding = dynamic_encodings<encoding::known_encodings>;

template <typename DefaultEncoding = encoding::hexdec, typename InputContext> constexpr auto select_runtime_encoding(InputContext && input) {
	return select_encoding<runtime_encoding, DefaultEncoding>(std::forward<InputContext>(input));
}

} // namespace cthash

#endif
