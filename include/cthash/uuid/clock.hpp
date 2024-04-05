#ifndef cthash_CLOCK_HPP
#define cthash_CLOCK_HPP

#include "uuid.hpp"
#include <chrono>

namespace cthash {

struct uuid_clock {
	using rep = std::chrono::microseconds::rep;
	using period = std::ratio<4, 1000>; // one tick is 4 microsecond
	using duration = std::chrono::duration<rep, period>;
	using time_point = std::chrono::time_point<uuid_clock, duration>;

	static constexpr bool is_steady = true;

	static constexpr auto epoch_start = std::chrono::sys_days{std::chrono::January / 1 / 1980};

	static auto now() noexcept -> time_point {
		return time_point{std::chrono::duration_cast<duration>(std::chrono::system_clock::now() - epoch_start)};
	}
};

constexpr auto to_time_six_octet(const uuid_like auto & id) noexcept {
	return static_cast<uint64_t>(id.time_high()) << 16u | static_cast<uint64_t>(id.time_low());
}

constexpr auto to_timepoint(const uuid_like auto & id) noexcept {
	return cthash::uuid_clock::time_point{cthash::uuid_clock::duration{to_time_six_octet(id)}};
}

} // namespace cthash

#if __cpp_lib_chrono >= 201907L

namespace std::chrono {

template <> struct clock_time_conversion<cthash::uuid_clock, std::chrono::system_clock> {
	using source = std::chrono::system_clock;
	using target = cthash::uuid_clock;

	template <typename Duration> constexpr auto operator()(const std::chrono::time_point<source, Duration> & t) const -> std::chrono::time_point<target, Duration> {
		return std::chrono::time_point<target, Duration>{t.time_since_epoch() - std::chrono::duration_cast<Duration>(cthash::uuid_clock::epoch_start.time_since_epoch())};
	}
};

template <> struct clock_time_conversion<std::chrono::system_clock, cthash::uuid_clock> {
	using source = cthash::uuid_clock;
	using target = std::chrono::system_clock;

	template <typename Duration> constexpr auto operator()(const std::chrono::time_point<source, Duration> & t) const -> std::chrono::time_point<target, Duration> {
		return std::chrono::time_point<target, Duration>{t.time_since_epoch() + std::chrono::duration_cast<Duration>(cthash::uuid_clock::epoch_start.time_since_epoch())};
	}
};

} // namespace std::chrono

#endif

#endif
