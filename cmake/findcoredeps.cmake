cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 14)

#cmake_policy(SET CMP0079 NEW)

set(CORE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)


set(DEP_DIR ${CORE_DIR}/../deps CACHE PATH "Dependencies")
option(USE_MBEDTLS "Use mbed TLS instead of OpenSSL")

if (DEFINED ENV{DEP_DIR})
    message(WARNING "Overriding DEP_DIR setting with environment variable")
    set(DEP_DIR $ENV{DEP_DIR})
endif ()

# Include our DEP_DIR in path used to find libraries


function(add_core_dependencies target)
    if (APPLE)
        set(PLAT osx)
    elseif (WIN32)
        set(PLAT amd64)
    else ()
        set(PLAT linux)
    endif ()

    set(CORE_INCLUDES
            ${CORE_DIR}
            ${DEP_DIR}/asio/asio/include
            )
    set(CORE_DEFINES
            -DASIO_STANDALONE
            -DUSE_ASIO
            -DHAVE_LZ4
            -DLZ4_DISABLE_DEPRECATE_WARNINGS
            -DMBEDTLS_DEPRECATED_REMOVED
            )

    if (WIN32)
        list(APPEND CMAKE_PREFIX_PATH
                ${DEP_DIR}/${PLAT}/mbedtls
                ${DEP_DIR}/${PLAT}/lz4/lib
                )
        list(APPEND CMAKE_LIBRARY_PATH
                ${DEP_DIR}/${PLAT}/mbedtls/library
                )
        list(APPEND CORE_INCLUDES
                ${DEP_DIR}/${PLAT}/asio/asio/include
                ${DEP_DIR}/${PLAT}/lz4/lz4/include
                ${DEP_DIR}/${PLAT}/tap-windows/src
                )
        list(APPEND CORE_DEFINES
                -D_WIN32_WINNT=0x0600
                -DTAP_WIN_COMPONENT_ID=tap0901
                -D_CRT_SECURE_NO_WARNINGS
                )
        set(EXTRA_LIBS fwpuclnt.lib Iphlpapi.lib)
        target_compile_options(${target} PRIVATE "/bigobj")
    else ()
        list(APPEND CMAKE_PREFIX_PATH
                ${DEP_DIR}/mbedtls/mbedtls-${PLAT}
                ${DEP_DIR}/lz4/lz4-${PLAT}
                )
        list(APPEND CMAKE_LIBRARY_PATH
                ${DEP_DIR}/mbedtls/mbedtls-${PLAT}/library
                )
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

    find_package(LZ4 REQUIRED)
    list(APPEND CORE_INCLUDES ${LZ4_INCLUDE_DIR})

    target_include_directories(${target} PRIVATE ${CORE_INCLUDES})
    target_compile_definitions(${target} PRIVATE ${CORE_DEFINES})
    target_link_libraries(${target} ${SSL_LIBRARY} ${EXTRA_LIBS} ${LZ4_LIBRARY})
endfunction()