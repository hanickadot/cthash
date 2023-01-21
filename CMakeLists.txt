cmake_minimum_required(VERSION 3.14)

project(cthash VERSION 1.0 LANGUAGES CXX)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(colors)

add_subdirectory(include)

option(CTHASH_TESTS "Enable CTHASH testing" ON)

if (CTHASH_TESTS)
  add_subdirectory(tests)
endif()
