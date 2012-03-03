// SWIG interface file for OpenVPN client

// enable director feature for OpenVPNClientBase virtual method callbacks
%module(directors="1") ovpncli
%feature("director") OpenVPNClient;

%include "std_string.i" // for std::string typemaps
%include "std_vector.i"

// top-level C++ implementation file
%{
#include "ovpncli.ipp"
%}

// modify exported C++ class names to incorporate their enclosing namespace
%rename(ClientAPI_OpenVPNClient) OpenVPNClient;
%rename(ClientAPI_TunBuilderBase) TunBuilderBase;
%rename(ClientAPI_ServerEntry) ServerEntry;
%rename(ClientAPI_EvalConfig) EvalConfig;
%rename(ClientAPI_DynamicChallenge) DynamicChallenge;
%rename(ClientAPI_ProvideCreds) ProvideCreds;
%rename(ClientAPI_Config) Config;
%rename(ClientAPI_Event) Event;
%rename(ClientAPI_Status) Status;
%rename(ClientAPI_LogInfo) LogInfo;

// declare vectors
namespace std {
  %template(ClientAPI_ServerEntryVector) vector<openvpn::ClientAPI::ServerEntry>;
};

// interface to be bridged between C++ and target language
%include "openvpn/tun/builder/base.hpp"
%include "ovpncli.hpp"
