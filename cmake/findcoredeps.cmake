cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 14)

#cmake_policy(SET CMP0079 NEW)

set(CORE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)


set(DEP_DIR ${CORE_DIR}/../deps CACHE PATH "Dependencies")
option(USE_MBEDTLS "Use mbed TLS instead of OpenSSL")

option(USE_WERROR "Treat compiler warnings as errors (-Werror)")

if (DEFINED ENV{DEP_DIR})
    message(WARNING "Overriding DEP_DIR setting with environment variable")
    set(DEP_DIR $ENV{DEP_DIR})
endif ()

# Include our DEP_DIR in path used to find libraries

if (APPLE)
    set(OPENVPN_PLAT osx)
elseif (WIN32)
    set(OPENVPN_PLAT amd64)
else ()
    set(OPENVPN_PLAT linux)
endif ()


function(add_core_dependencies target)
    set(PLAT ${OPENVPN_PLAT})

    set(CORE_INCLUDES
            ${CORE_DIR}
            )
    set(CORE_DEFINES
            -DASIO_STANDALONE
            -DUSE_ASIO
            -DHAVE_LZ4
            -DLZ4_DISABLE_DEPRECATE_WARNINGS
            -DMBEDTLS_DEPRECATED_REMOVED
            )

    if (WIN32)
        list(APPEND CORE_DEFINES
                -D_WIN32_WINNT=0x0600
                -DTAP_WIN_COMPONENT_ID=tap0901
                -D_CRT_SECURE_NO_WARNINGS
                )
        set(EXTRA_LIBS fwpuclnt.lib Iphlpapi.lib Wininet.lib Setupapi.lib Rpcrt4.lib Wtsapi32.lib lz4::lz4)
        if ("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "ARM64")
            # by some reasons CMake doesn't add those for ARM64
            list(APPEND EXTRA_LIBS advapi32.lib Ole32.lib Shell32.lib)
        endif ()

        target_compile_options(${target} PRIVATE "/bigobj")

        find_package(lz4 CONFIG REQUIRED)
        list(APPEND CORE_INCLUDES ${ASIO_INCLUDE_DIR})
    else ()
        list(APPEND CORE_INCLUDES
                ${DEP_DIR}/asio/asio/include
                )
        list(APPEND CMAKE_PREFIX_PATH
                ${DEP_DIR}/mbedtls/mbedtls-${PLAT}
                ${DEP_DIR}/lz4/lz4-${PLAT}
                )
        list(APPEND CMAKE_LIBRARY_PATH
                ${DEP_DIR}/mbedtls/mbedtls-${PLAT}/library
                )

        find_package(LZ4 REQUIRED)
    endif ()


    if (${USE_MBEDTLS})
        find_package(mbedTLS REQUIRED)

        set(SSL_LIBRARY ${MBEDTLS_LIBRARIES})

        list(APPEND CORE_DEFINES -DUSE_MBEDTLS)

        # The findmbedTLS does not set these automatically :(
        list(APPEND CORE_INCLUDES ${MBEDTLS_INCLUDE_DIR})

    else ()
        find_package(OpenSSL REQUIRED)
        SET(SSL_LIBRARY OpenSSL::SSL)
        list(APPEND CORE_DEFINES -DUSE_OPENSSL)
    endif ()

    if (APPLE)
        find_library(coreFoundation CoreFoundation)
        find_library(iokit IOKit)
        find_library(coreServices CoreServices)
        find_library(systemConfiguration SystemConfiguration)
        target_link_libraries(${target} ${coreFoundation} ${iokit} ${coreServices} ${systemConfiguration} ${lz4} ${SSL_LIBRARY})
    endif()

    if(UNIX)
        target_link_libraries(${target} pthread)
    endif()

    list(APPEND CORE_INCLUDES ${LZ4_INCLUDE_DIR})

    target_include_directories(${target} PRIVATE ${CORE_INCLUDES})
    target_compile_definitions(${target} PRIVATE ${CORE_DEFINES})
    target_link_libraries(${target} ${SSL_LIBRARY} ${EXTRA_LIBS} ${LZ4_LIBRARY})



    if (USE_WERROR)
        if (MSVC)
            target_compile_options(${target} PRIVATE /WX)
        else ()
            target_compile_options(${target} PRIVATE -Werror)
        endif ()
    endif ()


    if (MSVC)
        # I think this is too much currently
        # target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wsign-compare)
    endif()

endfunction()

function (add_json_library target)
    if (WIN32)
        find_package(jsoncpp CONFIG REQUIRED)
        target_link_libraries(${target} jsoncpp_lib)
        target_compile_definitions(${target} PRIVATE -DHAVE_JSONCPP)
        message("Adding jsoncpp to " ${target})
    else ()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(JSONCPP jsoncpp)
        target_link_libraries(${target} ${JSONCPP_LDFLAGS})
        target_include_directories(${target} PRIVATE ${JSONCPP_INCLUDE_DIRS})
    endif ()
endfunction ()
