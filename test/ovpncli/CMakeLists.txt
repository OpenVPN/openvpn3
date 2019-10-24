cmake_minimum_required(VERSION 3.5)

project(ovpncli)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake;${CMAKE_MODULE_PATH}")
include(findcoredeps)


add_executable(ovpncli
  cli.cpp)

add_core_dependencies(ovpncli)
