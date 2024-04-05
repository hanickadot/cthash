#include <cthash/sha3/sha3-256.hpp>
#include <cthash/uuid/clock.hpp>
#include <cthash/uuid.hpp>
#include <iostream>

int main() {
	using namespace cthash::literals;

	constexpr auto id = "550e8400-e29b-41d4-a716-446655441234"_uuid_v1;
	constexpr std::chrono::time_point ts = to_timepoint(id);

	std::cout << "id = " << id << "\n";
	std::cout << "4 microseconds since epoch: " << std::hex << ts.time_since_epoch().count() << "\n";
	std::cout << "reserved: " << std::hex << id.reserved() << "\n";
	std::cout << "family: " << std::hex << unsigned(id.family()) << "\n";
	std::cout << "node: " << std::dec << id.node() << "\n";

	constexpr auto hashed = cthash::sha3_256{}.update(id).final();

	std::cout << "z_base32(sha3_256(id)) = '" << cthash::z_base32_encode(hashed) << "'\n";
}