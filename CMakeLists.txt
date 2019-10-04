cmake_minimum_required(VERSION 3.15)
project(xxtea)

add_executable(xxtea main.cpp lib/base64/base64.hpp)

target_compile_features(xxtea PRIVATE  cxx_std_17)
target_include_directories(xxtea PRIVATE lib/)