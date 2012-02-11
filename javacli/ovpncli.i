// SWIG interface file for OpenVPN client

// enable director feature for OpenVPNClient virtual method callbacks
%module(directors="1") ovpncli
%feature("director") OpenVPNClient;

%include "std_string.i" // for std::string typemaps

// top-level C++ implementation file
%{
#include "ovpncli.ipp"
%}

// interface to be bridged between C++ and java
%include "ovpncli.hpp"
