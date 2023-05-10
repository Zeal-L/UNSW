cmake_minimum_required(VERSION 3.0)

project(COMP6771_ASS3 LANGUAGES CXX)

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
  #-Wzero-as-null-pointer-constant
  -Wno-self-assign-overloaded
  -Wno-self-move
  -Wsuggest-override
  -fstack-protector-strong
)

# debug builds should be compiled with sanitizers
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_EXE_LINKER_FLAGS_DEBUG_INIT "-fsanitize=address,undefined")
set(CMAKE_CXX_EXE_LINKER_FLAGS_RELWITHDEBINFO_INIT "-fsanitize=address,undefined")


# add the testing library
enable_testing()
add_library(catch2_main lib/catch2_main.cpp)
target_include_directories(catch2_main PUBLIC lib)

# -------------- MODIFY BELOW THIS LINE --------------- #

# XXX add libraries/executables here {{{
add_library(pipeline src/pipeline.cpp)


# }}}


# XXX add your tests here {{{
link_libraries(pipeline)
add_executable(client src/client.cpp)

link_libraries(catch2_main)

add_executable(pipeline_test_exe src/pipeline.test.cpp)
add_test(pipeline_test pipeline_test_exe)

# }}}

