include(findcoredeps)

add_executable(ovpnagent ovpnagent.cpp)
add_core_dependencies(ovpnagent)
add_json_library(ovpnagent)
