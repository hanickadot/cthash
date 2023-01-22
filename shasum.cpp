#include <cthash/cthash.hpp>
#include <chrono>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <iostream>

struct mapped_file {
	static constexpr int invalid = -1;

	int fd{invalid};
	size_t sz{0};
	void * ptr{nullptr};

	static size_t get_size(int fd) {
		if (fd == invalid) {
			return 0;
		}

		return (size_t)lseek(fd, 0, SEEK_END);
	}

	mapped_file(const char * path): fd{open(path, O_RDONLY)}, sz{get_size(fd)}, ptr{mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0)} { }

	mapped_file(const mapped_file &) = delete;
	mapped_file(mapped_file &&) = delete;

	~mapped_file() {
		if (ptr && fd != invalid) {
			munmap(ptr, sz);
			close(fd);
		}
	}

	auto get_span() const noexcept {
		return std::span<const std::byte>(reinterpret_cast<std::byte *>(ptr), sz);
	}
};

int main(int argc, char ** argv) {
	if (argc < 3) {
		std::cerr << argv[0] << " hash file\n";
		return 1;
	}

	const auto h = std::string_view(argv[1]);
	const auto f = mapped_file(argv[2]);

	if (f.fd == mapped_file::invalid) {
		std::cerr << "can't open file!\n";
		return 1;
	}

	const auto start = std::chrono::high_resolution_clock::now();

	if (h == "224") {
		std::cout << cthash::sha224{}.update(f.get_span()).final() << "\n";
	} else if (h == "256") {
		std::cout << cthash::sha256{}.update(f.get_span()).final() << "\n";
	} else if (h == "384") {
		std::cout << cthash::sha384{}.update(f.get_span()).final() << "\n";
	} else if (h == "512") {
		std::cout << cthash::sha512{}.update(f.get_span()).final() << "\n";
	} else if (h == "512224") {
		std::cout << cthash::sha512t<224>{}.update(f.get_span()).final() << "\n";
	} else if (h == "512256") {
		std::cout << cthash::sha512t<256>{}.update(f.get_span()).final() << "\n";
	} else {
		std::cerr << "unknown hash function!\n";
		return 1;
	}

	const auto end = std::chrono::high_resolution_clock::now();
	const auto dur = end - start;

	std::cerr << "and it took " << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() << " ms\n";
}