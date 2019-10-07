cmake_minimum_required(VERSION 3.15)
project(xxtea)

add_executable(xxtea main.cpp xxtea.hpp)

target_compile_features(xxtea PRIVATE  cxx_std_11)