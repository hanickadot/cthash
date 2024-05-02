#ifndef CTHASH_ENCODING_CHUNK_OF_BITS_HPP
#define CTHASH_ENCODING_CHUNK_OF_BITS_HPP

#include "bit-buffer.hpp"
#include <iostream>
#include <ranges>

namespace cthash {

template <typename Buffer> struct buffer_result_type;

template <typename Buffer> requires(Buffer::aligned()) struct buffer_result_type<Buffer> {
	typename Buffer::out_type value;
	static constexpr Buffer::size_type missing_bits = {0u};

	constexpr bool is_padding() const noexcept {
		return false;
	}
};

template <typename Buffer> requires(!Buffer::aligned()) struct buffer_result_type<Buffer> {
	typename Buffer::out_type value;
	typename Buffer::size_type missing_bits;

	constexpr bool is_padding() const noexcept {
		return missing_bits == Buffer::out_bits;
	}
};

template <typename Buffer, bool AllowPadding> struct buffer_with_missing_bits;

template <typename Buffer, bool AllowPadding> requires(Buffer::aligned()) struct buffer_with_missing_bits<Buffer, AllowPadding> {
	Buffer buffer{};

	struct result_type {
		typename Buffer::out_type value;
		static constexpr Buffer::size_type missing_bits = {0u};

		constexpr bool is_padding() const noexcept {
			return false;
		}
	};

	static constexpr bool aligned = Buffer::aligned();

	constexpr friend bool operator==(const buffer_with_missing_bits & lhs, const buffer_with_missing_bits & rhs) noexcept = default;

	constexpr auto front() const noexcept {
		return result_type{buffer.front()};
	}

	constexpr bool empty() const noexcept {
		return buffer.empty();
	}

	constexpr void pop() noexcept {
		return buffer.pop();
	}

	template <typename It, typename End> constexpr void feed_buffer(It & it, End end) noexcept {
		using input_value_type = std::iterator_traits<It>::value_type;

		while (!buffer.has_bits_for_pop() && (it != end)) {
			buffer.push(static_cast<std::make_unsigned_t<input_value_type>>(*it));
			++it;
		}
	}
};

template <typename Buffer, bool AllowPadding> requires(!Buffer::aligned()) struct buffer_with_missing_bits<Buffer, AllowPadding> {
	Buffer buffer{};
	Buffer::size_type missing_bits{0};

	static constexpr bool aligned = Buffer::aligned();

	struct result_type {
		typename Buffer::out_type value;
		typename Buffer::size_type missing_bits;

		constexpr bool is_padding() const noexcept {
			return missing_bits == Buffer::out_bits;
		}
	};

	constexpr friend bool operator==(const buffer_with_missing_bits & lhs, const buffer_with_missing_bits & rhs) noexcept = default;

	constexpr auto front() const noexcept {
		assert(Buffer::out_bits >= missing_bits);
		return result_type{buffer.front(), missing_bits};
	}

	constexpr bool empty() const noexcept {
		return buffer.empty();
	}

	constexpr void pop() noexcept {
		return buffer.pop();
	}

	constexpr void pad_buffer() noexcept requires(AllowPadding) {
		// full multi-chunk padding (for baseN encodings)
		missing_bits = (Buffer::out_bits - buffer.push_zeros_for_padding());
	}

	constexpr void pad_buffer() noexcept requires(!AllowPadding) {
		// only add enough zero to finish current output chunk
		missing_bits = buffer.push_zeros_to_align();
	}

	constexpr void saturate_missing_bits() noexcept requires(AllowPadding) {
		if (missing_bits) {
			missing_bits = Buffer::out_bits;
		}
		// missing_bits = static_cast<buffer_size_t>((unsigned)(bool)missing_bits * output_value_bit_size);
	}

	constexpr void saturate_missing_bits() noexcept requires(!AllowPadding) {
		// do nothing :)
	}

	template <typename It, typename End> constexpr void feed_buffer(It & it, End end) noexcept {
		using input_value_type = std::iterator_traits<It>::value_type;

		for (;;) {
			if (it == end) {
				if (buffer.has_bits_for_pop()) {
					// if this is second pass after padding we can mark all bits as missing
					saturate_missing_bits();
				} else {
					// fill remainder of buffer with zeros
					pad_buffer();
				}

				return;
			}

			if (buffer.has_bits_for_pop()) {
				return;
			}

			buffer.push(static_cast<std::make_unsigned_t<input_value_type>>(*it));
			++it;
		}
	}
};

template <bool Value> struct conditional;

template <> struct conditional<true> {
	template <typename T, typename> using type = T;
};

template <> struct conditional<false> {
	template <typename, typename T> using type = T;
};

template <bool Const, typename T> using maybe_const = typename conditional<Const>::template type<const T, T>;

template <typename T> concept integral_like = std::integral<T> || std::same_as<std::byte, T>;

template <size_t Bits, bool AllowPadding, std::ranges::input_range Input> requires integral_like<std::ranges::range_value_t<Input>> struct chunk_of_bits_view {
	using input_value_type = std::ranges::range_value_t<Input>;

	static constexpr size_t output_value_bit_size = Bits;
	static constexpr size_t input_value_bit_size = sizeof(input_value_type) * 8u;
	using buffer_t = cthash::bit_buffer<output_value_bit_size, input_value_bit_size>;
	using buffer_size_t = buffer_t::size_type;
	Input input;

	static constexpr bool aligned = buffer_t::aligned;

	struct sentinel { };

	template <bool Const> struct iterator {
		using parent = maybe_const<Const, Input>;
		using storage_type = buffer_with_missing_bits<buffer_t, AllowPadding>;
		using value_type = storage_type::result_type;
		using difference_type = intptr_t;

		std::ranges::iterator_t<parent> it;
		[[no_unique_address]] std::ranges::sentinel_t<parent> end;

		storage_type buffer{};

		constexpr iterator(parent & p) noexcept: it{std::ranges::begin(p)}, end{std::ranges::end(p)} {
			// initialize
			buffer.feed_buffer(it, end);
		}

		iterator(const iterator &) = default;
		iterator(iterator &&) = default;

		iterator & operator=(const iterator &) = default;
		iterator & operator=(iterator &&) = default;

		constexpr iterator & operator++() noexcept {
			buffer.pop();
			buffer.feed_buffer(it, end);
			return *this;
		}

		constexpr iterator operator++(int) noexcept {
			auto copy = *this;
			this->operator++();
			return copy;
		}

		constexpr auto operator*() const noexcept {
			return buffer.front();
		}

		constexpr friend bool operator==(const iterator & lhs, const iterator & rhs) noexcept = default;

		constexpr friend bool operator==(const iterator & self, sentinel) noexcept {
			return self.buffer.empty();
		}
	};

	static_assert(std::input_iterator<iterator<true>>);
	static_assert(std::input_iterator<iterator<false>>);
	static_assert(std::sentinel_for<sentinel, iterator<true>>);
	static_assert(std::sentinel_for<sentinel, iterator<false>>);

	constexpr chunk_of_bits_view(Input _input) noexcept: input{_input} { }

	constexpr auto begin() const noexcept {
		return iterator<true>{input};
	}

	constexpr auto begin() noexcept {
		return iterator<false>{input};
	}

	constexpr auto end() const noexcept {
		return sentinel{};
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<Input> && AllowPadding) {
		// calculate with blocks
		return ((std::ranges::size(input) + (buffer_t::in_capacity() - 1u)) / buffer_t::in_capacity()) * buffer_t::out_capacity();
	}

	constexpr size_t size() const noexcept requires(std::ranges::sized_range<Input> && !AllowPadding) {
		// calculate with bits
		const size_t bit_size_of_input = std::ranges::size(input) * input_value_bit_size;
		return (bit_size_of_input + (output_value_bit_size - 1u)) / output_value_bit_size;
	}
};

template <size_t Bits, bool AllowPadding> struct chunk_of_bits_action {
	template <std::ranges::input_range R> constexpr friend auto operator|(R && input, chunk_of_bits_action action) {
		return action.operator()<R>(std::forward<R>(input));
	}
	template <std::ranges::input_range R> constexpr auto operator()(R && input) {
		return chunk_of_bits_view<Bits, AllowPadding, R>(std::forward<R>(input));
	}
};

template <size_t Bits, bool AllowPadding = false> constexpr auto chunk_of_bits = chunk_of_bits_action<Bits, AllowPadding>{};

} // namespace cthash

#endif
