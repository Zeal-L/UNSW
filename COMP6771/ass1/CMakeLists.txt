cmake_minimum_required(VERSION 3.0)

project(COMP6771_ASS1 LANGUAGES CXX)

if(${PROJECT_SOURCE_DIR} STREQUAL ${PROJECT_BINARY_DIR})
  message(FATAL_ERROR "In-source builds are not supported. Please make a new directory and run cmake from there.")
endif()

# we use C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# helpful compiler flags for gcc/clang
add_compile_options(
  -Wall
  -Wextra
  -Werror
  -pedantic-errors
  -Wconversion
  -Wsign-conversion
  -Wdouble-promotion
  -Wcast-align
  -Wformat=2
  -Wuninitialized
  -Wnull-dereference
  -Wnon-virtual-dtor
  -Woverloaded-virtual
  -Wdeprecated-copy-dtor
  -Wold-style-cast
  -Wzero-as-null-pointer-constant
#  -Wsuggest-override
  -fstack-protector-strong
)

# debug builds should be compiled with sanitizers
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_EXE_LINKER_FLAGS_DEBUG_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_EXE_LINKER_FLAGS_RELWITHDEBINFO_INIT "-fsanitize=address,undefined")

# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -no-pie")
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fopenmp")


# add the testing library
enable_testing()
add_library(catch2_main lib/catch2_main.cpp)
target_include_directories(catch2_main PUBLIC lib)

# make sure english.txt is with the build files
configure_file(src/english.txt english.txt COPYONLY)

# -------------- MODIFY BELOW THIS LINE --------------- #

# XXX add libraries/executables here {{{
add_library(word_ladder src/word_ladder.cpp)

# }}}


# XXX add your tests here {{{
link_libraries(catch2_main)
link_libraries(word_ladder)

add_executable(debugging src/main.cpp)

add_executable(word_ladder_test_exe src/word_ladder.test.cpp)
add_executable(word_ladder_benchmark_exe src/word_ladder_benchmark.test.cpp)

add_test(word_ladder_test word_ladder_test_exe)
add_test(word_ladder_benchmark word_ladder_benchmark_exe)

# }}}

