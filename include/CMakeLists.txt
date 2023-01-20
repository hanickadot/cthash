add_library(cthash INTERFACE)

target_compile_features(cthash INTERFACE cxx_std_23)
target_include_directories(cthash INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_sources(cthash INTERFACE FILE_SET headers TYPE HEADERS FILES
	cthash/sha2.hpp
)
