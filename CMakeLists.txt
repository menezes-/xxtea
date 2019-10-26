cmake_minimum_required(VERSION 3.15)
project(xxtea)

add_executable(xxtea main.cpp xxtea.hpp)

target_compile_features(xxtea PRIVATE  cxx_std_11)

add_library(xxtea-php SHARED xxtea-php.cpp)

target_compile_features(xxtea-php PRIVATE cxx_std_11)

find_library(PHP_CPP NAMES libphpcpp phpcpp)

target_link_libraries(xxtea-php PRIVATE ${PHP_CPP_LIBRARIES})
target_include_directories(xxtea-php PRIVATE ${PHP_CPP_INCLUDE_DIRS})