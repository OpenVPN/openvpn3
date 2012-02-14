// SWIG interface file for OpenVPN client

// enable director feature for OpenVPNClientBase virtual method callbacks
%module(directors="1") ovpncli
%feature("director") OpenVPNClientBase;

%include "std_string.i" // for std::string typemaps

// top-level C++ implementation file
%{
#include "ovpncli.ipp"
%}

// interface to be bridged between C++ and java
%include "ovpncli.hpp"
