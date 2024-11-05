if (MSVC)
    find_package(GTest CONFIG REQUIRED)
    set(GTEST_LIB GTest::gtest_main)
else()
    set(GTEST_LIB gtest_main)
    if(NOT OVPN_GTEST_VERSION)
        # renovate: datasource=github-releases depName=google/googletest
        set(OVPN_GTEST_VERSION v1.15.0)
    endif()

    include(FetchContent)

    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        ${OVPN_GTEST_VERSION}
        )
    FetchContent_MakeAvailable(googletest)

endif ()
