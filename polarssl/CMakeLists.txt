cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -O3 -Wall -W -Wdeclaration-after-statement")
endif(CMAKE_COMPILER_IS_GNUCC)
 
if(LIB_INSTALL_DIR)
else()
set(LIB_INSTALL_DIR lib)
endif()

include_directories(include/)

add_subdirectory(library)
add_subdirectory(include)
add_subdirectory(programs)
