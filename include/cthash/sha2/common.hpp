#ifndef CTHASH_SHA2_COMMON_HPP
#define CTHASH_SHA2_COMMON_HPP

#include "../hasher.hpp"
#include <array>
#include <span>
#include <concepts>
#include <cstdint>

namespace cthash {

struct sha2_base {
	using length_type = uint64_t;

	template <std::unsigned_integral T> static constexpr auto choice(T e, T f, T g) noexcept -> T {
		return (e bitand f) xor (~e bitand g);
	}

	template <std::unsigned_integral T> static constexpr auto majority(T a, T b, T c) noexcept -> T {
		return (a bitand b) xor (a bitand c) xor (b bitand c);
	}

	template <const auto & Config, typename StageT, size_t StageLength, typename StateT, size_t StateLength> static constexpr void rounds(std::span<const StageT, StageLength> w, std::array<StateT, StateLength> & state) noexcept {
		using state_t = std::array<StateT, StateLength>;

		// create copy of internal state
		auto wvar = state_t(state);

		// just give them names
		auto & a = wvar[0];
		auto & b = wvar[1];
		auto & c = wvar[2];
		auto & d = wvar[3];
		auto & e = wvar[4];
		auto & f = wvar[5];
		auto & g = wvar[6];
		auto & h = wvar[7];

		for (int i = 0; i != Config.rounds_number; ++i) {
			const auto temp1 = h + Config.sum_e(e) + choice(e, f, g) + Config.constants[i] + w[i];
			const auto temp2 = Config.sum_a(a) + majority(a, b, c);

			// move around
			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// add store back
		for (int i = 0; i != (int)state.size(); ++i) {
			state[i] += wvar[i];
		}
	}
};

} // namespace cthash

#endif