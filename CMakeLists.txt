cmake_minimum_required(VERSION 3.14)

project(cthash VERSION 1.0 LANGUAGES CXX)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(colors)
include(coverage)

option(CTHASH_TESTS "Enable CTHASH testing" ON)

if (CTHASH_TESTS)
	option(CTHASH_COVERAGE "Enable CTHASH test-coverage" ON)

	if (CTHASH_COVERAGE)
		enable_coverage()
	endif()

	add_subdirectory(tests)
endif()

add_subdirectory(include)