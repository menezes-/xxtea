cmake_minimum_required(VERSION 3.15)
project(xxtea)

add_executable(xxtea main.cpp xxtea.hpp)

target_compile_features(xxtea PRIVATE  cxx_std_11)

add_library(xxtea-php SHARED xxtea-php.cpp)

target_compile_features(xxtea-php PRIVATE cxx_std_11)

find_library(PHP_CPP NAMES libphpcpp phpcpp)

target_link_libraries(xxtea-php PRIVATE ${PHP_CPP_LIBRARIES})
target_include_directories(xxtea-php PRIVATE ${PHP_CPP_INCLUDE_DIRS})

set_target_properties(xxtea-php PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(xxtea-php PRIVATE
                       -Wall -Wextra -Wno-unused-function
                       $<$<CONFIG:Debug>:-g -O0>
                       $<$<CONFIG:Release>:-O3 -s>
                       $<$<CONFIG:RelWithDebInfo>:-g -O3>
                       )
