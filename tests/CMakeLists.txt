message(STATUS "CTDB testing enabled")

find_package(Catch2 3 REQUIRED)

file(GLOB_RECURSE TESTS_SOURCES  LINK_DIRECTORIES false RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.cpp")

add_executable(test-runner ${TESTS_SOURCES})

target_link_libraries(test-runner PRIVATE Catch2::Catch2WithMain cthash)
target_compile_features(test-runner PUBLIC cxx_std_23)

add_custom_target(test test-runner DEPENDS test-runner)
add_custom_target(long-test test-runner "\[.long\]" DEPENDS test-runner)