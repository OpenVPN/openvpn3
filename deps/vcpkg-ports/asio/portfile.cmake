set(VCPKG_BUILD_TYPE release) # header-only

string(REPLACE "." "-" ref "asio-${VERSION}")
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO chriskohlhoff/asio
    REF "${ref}"
    SHA512 d44b35d9d1900de35aa10bf339c7e16a06e110377fd70fbefba91599d24cff32cc3dc88a4b0bf1e1706f9ac46177982edb5c7f969b72a57123be6550a3b062d8
    HEAD_REF master
    PATCHES
        ../../asio/patches/0001-Added-Apple-NAT64-support-when-both-ASIO_HAS_GETADDR.patch
        ../../asio/patches/0002-Added-user-code-hook-async_connect_post_open-to-be-c.patch
        ../../asio/patches/0003-error_code.ipp-Use-English-for-Windows-error-message.patch
        ../../asio/patches/0004-Added-kovpn-route_id-support-to-endpoints-for-sendto.patch
        ../../asio/patches/0005-basic_resolver_results-added-data-and-cdata-members-.patch
        ../../asio/patches/0006-reactive_socket_service_base-add-constructor-for-bas.patch
)
file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

# Always use "ASIO_STANDALONE" to avoid boost dependency
vcpkg_replace_string("${SOURCE_PATH}/asio/include/asio/detail/config.hpp" "defined(ASIO_STANDALONE)" "!defined(VCPKG_DISABLE_ASIO_STANDALONE)")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DPACKAGE_VERSION=${VERSION}
)
vcpkg_cmake_install()
vcpkg_fixup_pkgconfig()
    
vcpkg_cmake_config_fixup()
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/asio-config.cmake" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/asio/LICENSE_1_0.txt")
