add_executable(sha3 sha3.cpp)
target_link_libraries(sha3 cthash)

add_executable(sha256 sha256.cpp)
target_link_libraries(sha256 cthash)

add_executable(shake128 shake128.cpp)
target_link_libraries(shake128 cthash)

add_executable(xxhash xxhash.cpp)
target_link_libraries(xxhash cthash)

add_executable(playground playground.cpp)
target_link_libraries(playground cthash)