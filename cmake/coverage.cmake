SET(test_source "int main() { }")

try_compile(COVERAGE_WORKS SOURCE_FROM_VAR test.cpp test_source LINK_OPTIONS -fprofile-instr-generate -fcoverage-mapping OUTPUT_VARIABLE COVERAGE_WORKS_OUTPUT)

if (NOT COVERAGE_WORKS)
	#message(STATUS "test coverage is not compatible with current compiler")
	#message(STATUS "${COVERAGE_WORKS_OUTPUT}")
	function(enable_coverage)
	endfunction()
	
	function(coverage_report_after EVENT TARGET)
		add_custom_target(coverage DEPENDS ${EVENT})
	endfunction()
	
	unset(LLVM_COV)
	return()
endif()

cmake_path(GET CMAKE_CXX_COMPILER PARENT_PATH COMPILER_HINT_PATH)

if (NOT LLVM_PROFDATA)
	find_program(LLVM_PROFDATA llvm-profdata HINTS ${COMPILER_HINT_PATH})
endif()

if (NOT LLVM_COV)
	find_program(LLVM_COV llvm-cov HINTS ${COMPILER_HINT_PATH})
endif()

if (LLVM_PROFDATA AND LLVM_COV)
	set(LLVM_PROFDATA "${LLVM_PROFDATA}" CACHE INTERNAL "path to llvm-profdata")
	set(LLVM_COV "${LLVM_COV}" CACHE INTERNAL "path to llvm-cov")
else()
	find_program(XCRUN xcrun)
	if (XCRUN)
		set(LLVM_PROFDATA "${XCRUN} llvm-profdata" CACHE INTERNAL "path to llvm-profdata")
		set(LLVM_COV "${XCRUN} llvm-cov" CACHE INTERNAL "path to llvm-cov")
	endif()
endif()

find_program(OPEN_UTILITY open)
set(OPEN_UTILITY "${OPEN_UTILITY}" CACHE INTERNAL "path to open utility")

function(enable_coverage)
	
	if (NOT COVERAGE_WORKS)
		message(FATAL_ERROR "Source level code coverage is not supporter!")
	endif()
	
	if (NOT LLVM_COV)
		message(FATAL_ERROR "Source level code coverage is supported only for Clang compiler! (CMAKE_CXX_COMPILER_ID = ${CMAKE_CXX_COMPILER_ID})")
	endif()
	
	message(STATUS "Enabling Clang source code-coverage (llvm-cov=${LLVM_COV})")
	
	# add flags to emit coverage
	add_compile_options("-fprofile-instr-generate" "-fcoverage-mapping" "-g")
	add_link_options("-fprofile-instr-generate" "-fcoverage-mapping")
	add_compile_options("-ffile-prefix-map=${CMAKE_SOURCE_DIR}/=/")
endfunction()

function(coverage_report_after EVENT TARGET)
	if (NOT LLVM_COV)
		add_custom_target(coverage DEPENDS ${EVENT})
		return()
	endif()

	SET(coverage_data_name "default.profraw")
	add_custom_command(TARGET ${EVENT} POST_BUILD 
		COMMAND ${LLVM_PROFDATA} merge -sparse ${coverage_data_name} -o coverage.profdata 
		COMMAND ${LLVM_COV} show $<TARGET_FILE:${TARGET}> -format html -instr-profile=coverage.profdata "-ignore-filename-regex=\"(external/.*|tests/.*|cthash/internal/assert[.]hpp)\""  -output-dir ${CMAKE_BINARY_DIR}/report -show-instantiations=false -show-directory-coverage -show-expansions=false -show-line-counts --show-line-counts-or-regions -Xdemangler c++filt -Xdemangler -n -show-branches=percent -tab-size=4 -path-equivalence=/,${CMAKE_SOURCE_DIR} 
		COMMAND cd ${CMAKE_BINARY_DIR} && zip -q -r -9 report.zip report BYPRODUCTS  ${CMAKE_BINARY_DIR}/report.zip COMMENT "Generating Code-Coverage report"
	)
	
	add_custom_target(coverage DEPENDS ${CMAKE_BINARY_DIR}/report.zip)
	
	if (OPEN_UTILITY)
		add_custom_command(TARGET coverage POST_BUILD COMMAND ${OPEN_UTILITY} ${CMAKE_BINARY_DIR}/report/index.html DEPENDS ${CMAKE_BINARY_DIR}/report.zip)
	endif()
endfunction()
