# cmake -DENABLE_TESTING=1 -DOPENSSL_DIR=$OPENSSL_DIR -DOPENSSL_AES_NI=1 ../polarssl-1.1.1 && make

cmake_minimum_required(VERSION 2.6)
project(POLARSSL C)

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} $ENV{LIB_FPIC} $ENV{LIB_OPT_LEVEL} $ENV{PLATFORM_FLAGS} $ENV{OTHER_COMPILER_FLAGS} -Wall -W -Wdeclaration-after-statement")
endif(CMAKE_COMPILER_IS_GNUCC)

if(OPENSSL_DIR)
  add_library(minicrypto STATIC IMPORTED)
  set_property(TARGET minicrypto PROPERTY IMPORTED_LOCATION "${OPENSSL_DIR}/lib/libminicrypto.a")
  add_definitions(-DPOLARSSL_USE_OPENSSL_CRYPTO)
  add_definitions(-DPOLARSSL_USE_OPENSSL_BF)
  if(OPENSSL_AES_NI)
    add_definitions(-DPOLARSSL_USE_OPENSSL_AES_NI)
  endif()
endif()

if(EXTERNAL_RNG)
  add_definitions(-DEXTERNAL_RNG)
endif()
 
if(ENABLE_TESTING)
  add_definitions(-DENABLE_TESTING)
  enable_testing()
endif()
 
if(LIB_INSTALL_DIR)
else()
set(LIB_INSTALL_DIR lib)
endif()

include_directories(include/)

add_subdirectory(library)
add_subdirectory(include)

if(ENABLE_TESTING)
  if(CMAKE_COMPILER_IS_GNUCC)
    add_subdirectory(tests)
  endif(CMAKE_COMPILER_IS_GNUCC)
  add_subdirectory(programs)
endif()
