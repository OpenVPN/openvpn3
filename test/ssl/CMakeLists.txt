
add_executable(proto proto.cpp)
add_core_dependencies(proto)

if (NOT WIN32)
    # We have a number of private fields that depend on compile flags for manual testing
    target_compile_options(proto PRIVATE -Wno-unused-private-field)
endif ()
