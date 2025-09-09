cmake_minimum_required(VERSION 3.21)

project(cthash VERSION 1.0 LANGUAGES CXX)

if (PROJECT_IS_TOP_LEVEL)
set(CMAKE_CXX_STANDARD 20)
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(colors)

option(CTHASH_TESTS "Enable CTHASH testing" OFF)

if (CTHASH_TESTS)
	if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/external/catch2/CMakeLists.txt)
		message(STATUS "Using local copy of catch2")
		
		#set(CATCH_CONFIG_FAST_COMPILE ON)
		add_subdirectory(external/catch2 EXCLUDE_FROM_ALL SYSTEM)
	endif()
	
	option(CTHASH_COVERAGE "Enable CTHASH test-coverage" ON)

	if (CTHASH_COVERAGE)
		include(coverage)
		enable_coverage()
	else()
		message(STATUS "Test coverage measurement is OFF")
	endif()

	add_subdirectory(tests)
else()
	message(STATUS "Tests are disabled")
endif()

include(pedantic)

option(CTHASH_EXAMPLES "Build CTHASH examples" ON)

if (CTHASH_EXAMPLES)
	add_subdirectory(examples)
	
	add_executable(example example.cpp)
	target_link_libraries(example cthash)

	add_executable(checksum checksum.cpp)
	target_link_libraries(checksum cthash)
endif()

endif()

add_subdirectory(include)
