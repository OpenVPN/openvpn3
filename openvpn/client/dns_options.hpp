//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2022- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//


#pragma once

#include <map>
#include <vector>
#include <algorithm>
#include <sstream>

#include <openvpn/common/number.hpp>
#include <openvpn/common/option_error.hpp>
#include <openvpn/common/jsonlib.hpp>
#include <openvpn/common/hostport.hpp>
#include <openvpn/addr/ip.hpp>

#ifdef HAVE_JSON
#ifndef OPENVPN_JSON
#include <json/json.h>
#endif
#include <openvpn/common/jsonhelper.hpp>
#endif

namespace openvpn {

/**
 * @class DnsAddress
 * @brief A name server address and optional port
 */
struct DnsAddress
{
    DnsAddress() = default;
    virtual ~DnsAddress() noexcept = default;

    /**
     *  Constructs the DnsAddress object by parsing the input string
     *  into separate "address" and "port" fields.  If "port" is missing,
     *  it will be set to 0.
     *
     *  Supported formats:
     *      192.168.0.1
     *      192.168.0.1:53
     *      [2001:db8:1234::1]
     *      [2001:db8:1234::1]:53
     */
    explicit DnsAddress(const std::string &address_input)
    {
        IP::Addr addr;
        std::string addr_str = address_input;
        port = 0;

        bool ipv6_bracket_encaps = address_input.length() > 2
                                   && address_input[0] == '['
                                   && address_input.rfind(']') != std::string::npos;

        auto first_colon_pos = address_input.find(':');
        auto last_colon_pos = address_input.rfind(':');
        const bool v6_port_found = ipv6_bracket_encaps
                                   && last_colon_pos > address_input.rfind(']');

        const bool v4_port_found = first_colon_pos != std::string::npos
                                   && first_colon_pos == addr_str.rfind(':');

        if (v6_port_found || v4_port_found)
        {
            std::string port_str;
            if (!HostPort::split_host_port(address_input, addr_str, port_str, "", false, &port))
            {
                OPENVPN_THROW_EXCEPTION("Invalid address:port format '" << address_input << "'");
            }

            // If it was an IPv6 address, the bracket encapsulation has been removed
            // by HostPort::split_host_port()
            ipv6_bracket_encaps = false;
        }

        try
        {
            if (ipv6_bracket_encaps)
            {
                addr_str = addr_str.substr(1, addr_str.length() - 2);
            }
            addr = IP::Addr(addr_str, "dns-ip-address");
        }
        catch (const IP::ip_exception &)
        {
            OPENVPN_THROW_EXCEPTION("Invalid address '" << addr_str << "'");
        }
        address = addr.to_string();
    }


    /**
     * @brief Return string representation of the IP address
     *        and port stored in the DnsAddress object.
     *
     *        The output of this method is expected to be
     *        parsable by this class constructor.
     *
     * @return std::string  the string representation generated
     */
    std::string to_string() const
    {
        std::ostringstream os;

        const IP::Addr addr(address);
        os << (addr.is_ipv6() && port ? "[" : "")
           << address
           << (addr.is_ipv6() && port ? "]" : "");

        if (port)
        {
            os << ":" << port;
        }
        return os.str();
    }

    void validate(const std::string &title) const
    {
        IP::Addr::validate(address, title);
    }

#ifdef HAVE_JSON
    Json::Value to_json() const
    {
        Json::Value root(Json::objectValue);
        root["address"] = Json::Value(address);
        if (port)
        {
            root["port"] = Json::Value(port);
        }
        return root;
    }

    void from_json(const Json::Value &root, const std::string &title)
    {
        json::assert_dict(root, title);
        json::to_uint_optional(root, port, "port", 0U, title);

        std::string addr_str;
        json::to_string(root, addr_str, "address", title);
        address = IP::Addr::from_string(addr_str).to_string();
    }
#endif

    bool operator==(const DnsAddress &) const = default;

    std::string address;
    unsigned int port = 0;
};

/**
 * @class DnsDomain
 * @brief A DNS domain name
 */
struct DnsDomain
{
    DnsDomain() = default;
    virtual ~DnsDomain() noexcept = default;

    explicit DnsDomain(const std::string &domain_)
    {
        domain = domain_;
    }

    /**
     * @brief Return string representation of the DnsDomain object
     *
     * @return std::string  the string representation generated
     */
    std::string to_string() const
    {
        return domain;
    }

    void validate(const std::string &title) const
    {
        HostPort::validate_host(domain, title);
    }

#ifdef HAVE_JSON
    Json::Value to_json() const
    {
        return Json::Value(domain);
    }

    void from_json(const Json::Value &value, const std::string &title)
    {
        if (!value.isString())
        {
            throw json::json_parse("string " + title + " is of incorrect type");
        }
        domain = value.asString();
    }
#endif

    std::string domain;

    bool operator==(const DnsDomain &) const = default;
};

/**
 * @class DnsServer
 * @brief DNS settings for a name server
 */
struct DnsServer
{
    enum class Security
    {
        Unset,   ///<  Undefined setting; default value when not set
        No,      ///<  Do not use DNSSEC
        Yes,     ///<  Enforce using DNSSEC
        Optional ///<  Try to use DNSSEC opportunistically.  If it fails, the DNS resolver may ignore DNSSEC
    };

    /**
     * @brief Return string representation of a given DnsServer::Security
     *        value
     *
     * @param  dnssec DnsServer::Security value
     * @return std::string  the string representation generated
     */
    static std::string dnssec_string(const Security dnssec)
    {
        switch (dnssec)
        {
        case Security::No:
            return "No";
        case Security::Yes:
            return "Yes";
        case Security::Optional:
            return "Optional";
        default:
            return "Unset";
        }
    }


    /**
     * @brief Return string representation of the dnssec
     *        value in this DnsServer object
     *
     * @return std::string  the string representation generated
     */
    std::string dnssec_string() const
    {
        return dnssec_string(dnssec);
    }


    /**
     *  Parse the --dns server n dnssec VALUE into the
     *  internal DnsServer::Security representation.  This
     *  method is typically called from the option parser.
     *
     *  @param dnssec_value   std::string containing the DNSSEC setting to use
     *  @throws openvpn::Exception on invalid values
     */
    void parse_dnssec_value(const std::string &dnssec_value)
    {
        if (dnssec_value == "yes")
        {
            dnssec = DnsServer::Security::Yes;
        }
        else if (dnssec_value == "no")
        {
            dnssec = DnsServer::Security::No;
        }
        else if (dnssec_value == "optional")
        {
            dnssec = DnsServer::Security::Optional;
        }
        else
        {
            OPENVPN_THROW_EXCEPTION("Invalid DNSSEC value '" << dnssec_value << "'");
        }
    }

    enum class Transport
    {
        Unset, ///<  Undefined setting; default value when not set
        Plain, ///<  Use the classic unencrypted DNS protocol
        HTTPS, ///<  Use DNS-over-HTTPS (DoH)
        TLS    ///<  Use DNS-over-TLS (DoT)
    };

    /**
     * @brief Return string representation of a given DnsServer::Transport
     *        value
     *
     * @param  transport DnsServer::Transport value
     * @return std::string  the string representation generated
     */
    static std::string transport_string(const Transport transport)
    {
        switch (transport)
        {
        case Transport::Plain:
            return "Plain";
        case Transport::HTTPS:
            return "HTTPS";
        case Transport::TLS:
            return "TLS";
        default:
            return "Unset";
        }
    }

    /**
     * @brief Return string representation of a given DnsServer::Transport
     *        value
     *
     * @return std::string  the string representation generated
     */
    std::string transport_string() const
    {
        return transport_string(transport);
    }

    /**
     *  Parse the --dns server n transport VALUE into the
     *  internal DnsServer::Transport representation.  This
     *  method is typically called from the option parser.
     *
     *  @param transport_value   std::string containing the DNS transport setting to use
     *  @throws openvpn::Exception on invalid values
     */
    void parse_transport_value(const std::string &transport_value)
    {
        if (transport_value == "plain")
        {
            transport = DnsServer::Transport::Plain;
        }
        else if (transport_value == "DoH")
        {
            transport = DnsServer::Transport::HTTPS;
        }
        else if (transport_value == "DoT")
        {
            transport = DnsServer::Transport::TLS;
        }
        else
        {
            OPENVPN_THROW_EXCEPTION("Invalid transport value '" << transport_value << "'");
        }
    }

    DnsServer() = default;
    virtual ~DnsServer() noexcept = default;

#ifdef HAVE_JSON
    /**
     *  Instantiate a new DnsServer object with information from a JSON blob,
     *  typically exported using the DnsServer::to_json() method
     *
     *  @param root   The root Json::Value object to import
     *  @param title  std::string with details used for error logging
     */
    explicit DnsServer(const Json::Value &root, const std::string &title = "")
    {
        from_json(root, title);
    }
#endif

    /**
     *  Generate a human readable representation of the configured
     *  DnsServer variables
     *
     * @return std::string  the string representation generated
     */
    std::string to_string(const char *prefix = "") const
    {
        std::ostringstream os;
        os << prefix << "Addresses:\n";
        for (const auto &address : addresses)
        {
            os << prefix << "  " << address.to_string() << '\n';
        }
        if (!domains.empty())
        {
            os << prefix << "Domains:\n";
            for (const auto &domain : domains)
            {
                os << prefix << "  " << domain.to_string() << '\n';
            }
        }
        if (dnssec != Security::Unset)
        {
            os << prefix << "DNSSEC: " << dnssec_string(dnssec) << '\n';
        }
        if (transport != Transport::Unset)
        {
            os << prefix << "Transport: " << transport_string(transport) << '\n';
        }
        if (!sni.empty())
        {
            os << prefix << "SNI: " << sni << '\n';
        }
        return os.str();
    }

#ifdef HAVE_JSON
    /**
     *  Generate a JSON representation of the configured
     *  DnsServer variables.
     *
     *  The output of this function can be imported into
     *  another DnsServer object by passing the Json::Value
     *  to the DnsServer constructor or using the
     *  DnsServer::from_json() method.
     *
     * @return Json::Value of information this object carries
     */
    Json::Value to_json() const
    {
        Json::Value server(Json::objectValue);
        json::from_vector(server, addresses, "addresses");
        if (!domains.empty())
        {
            json::from_vector(server, domains, "domains");
        }
        if (dnssec != Security::Unset)
        {
            server["dnssec"] = Json::Value(dnssec_string(dnssec));
        }
        if (transport != Transport::Unset)
        {
            server["transport"] = Json::Value(transport_string(transport));
        }
        if (!sni.empty())
        {
            server["sni"] = Json::Value(sni);
        }
        return server;
    }

    /**
     *  Import a Json::Value, typically generated by DnsServer::to_json()
     *  which will reconfigure this object to carry the information from
     *  the JSON data.
     *
     *  @param root   The root Json::Value object to import
     *  @param title  std::string with details used for error logging
     */
    void from_json(const Json::Value &root, const std::string &title)
    {
        json::assert_dict(root, title);
        json::to_vector(root, addresses, "addresses", title);
        if (json::exists(root, "domains"))
        {
            json::to_vector(root, domains, "domains", title);
        }
        if (json::exists(root, "dnssec"))
        {
            std::string dnssec_str;
            json::to_string(root, dnssec_str, "dnssec", title);
            if (dnssec_str == "Optional")
            {
                dnssec = Security::Optional;
            }
            else if (dnssec_str == "Yes")
            {
                dnssec = Security::Yes;
            }
            else if (dnssec_str == "No")
            {
                dnssec = Security::No;
            }
            else
            {
                throw json::json_parse("dnssec value " + dnssec_str + "is unknown");
            }
        }
        if (json::exists(root, "transport"))
        {
            std::string transport_str;
            json::to_string(root, transport_str, "transport", title);
            if (transport_str == "Plain")
            {
                transport = Transport::Plain;
            }
            else if (transport_str == "HTTPS")
            {
                transport = Transport::HTTPS;
            }
            else if (transport_str == "TLS")
            {
                transport = Transport::TLS;
            }
            else
            {
                throw json::json_parse("transport value " + transport_str + "is unknown");
            }
        }
        json::to_string_optional(root, sni, "sni", "", title);
    }
#endif

    bool operator==(const DnsServer &at) const = default;

    //! Parsed from --dns server n address ADDRESS[:PORT] [...] or --dhcp-option DNS/DNS6
    std::vector<DnsAddress> addresses;

    //! Parsed from --dns server n resolve-domains DOMAIN [...] or --dhcp-option DOMAIN/DOMAIN-SEARCH if use_search_as_split_domains is true
    std::vector<DnsDomain> domains;

    //! Parsed from --dns server n dnssec {yes,optional,no}
    Security dnssec = Security::Unset;

    //! Parsed from --dns server n transport {plain,DoT,DoH}
    Transport transport = Transport::Unset;

    //! Parsed from --dns server n sni
    std::string sni;
};

/**
 * @class DnsOptions
 * @brief All DNS options set with the --dns or --dhcp-option directive
 */
struct DnsOptions
{
    DnsOptions() = default;
    ~DnsOptions() noexcept = default;

#ifdef HAVE_JSON
    /**
     *  Instantiate a new DnsOptions object with information from a JSON blob,
     *  typically exported using the DnsOptions::to_json() method
     *
     *  @param root   The root Json::Value object to import
     *  @param title  std::string with details used for error logging
     */
    explicit DnsOptions(const Json::Value &root, const std::string &title = "")
    {
        from_json(root, title);
    }
#endif

    /**
     *  Generate a human readable representation of the configured
     *  DnsOptions variables
     *
     * @return std::string  the string representation generated
     */
    std::string to_string() const
    {
        std::ostringstream os;
        if (!servers.empty())
        {
            os << "DNS Servers:\n";
            for (const auto &[priority, server] : servers)
            {
                os << "  Priority: " << priority << '\n';
                os << server.to_string("  ");
            }
        }
        if (!search_domains.empty())
        {
            os << "DNS Search Domains:\n";
            for (const auto &domain : search_domains)
            {
                os << "  " << domain.to_string() << '\n';
            }
        }
        os << "Values from dhcp-options: " << (from_dhcp_options ? "true" : "false") << '\n';
        return os.str();
    }

#ifdef HAVE_JSON
    /**
     *  Generate a JSON representation of the configured
     *  DnsOptions variables.
     *
     *  The output of this function can be imported into
     *  another DnsOptions object by passing the Json::Value
     *  to the DnsOptions constructor or using the
     *  DnsOptions::from_json() method.
     *
     * @return Json::Value of information this object carries
     */
    Json::Value to_json() const
    {
        Json::Value root(Json::objectValue);
        Json::Value servers_json(Json::objectValue);
        for (const auto &[prio, server] : servers)
        {
            servers_json[std::to_string(prio)] = server.to_json();
        }
        root["servers"] = std::move(servers_json);
        json::from_vector(root, search_domains, "search_domains");
        root["from_dhcp_options"] = Json::Value(from_dhcp_options);
        return root;
    }

    /**
     *  Import a Json::Value, typically generated by DnsOptions::to_json()
     *  which will reconfigure this object to carry the information from
     *  the JSON data.
     *
     *  @param root   The root Json::Value object to import
     *  @param title  std::string with details used for error logging
     */
    void from_json(const Json::Value &root, const std::string &title)
    {
        json::assert_dict(root, title);
        json::assert_dict(root["servers"], title);
        for (const auto &prio : root["servers"].getMemberNames())
        {
            DnsServer server(root["servers"][prio], title);
            servers[std::stoi(prio)] = std::move(server);
        }
        json::to_vector(root, search_domains, "search_domains", title);
        json::to_bool(root, from_dhcp_options, "from_dhcp_options", title);
    }
#endif

    bool operator==(const DnsOptions &at) const = default;

    bool from_dhcp_options = false;        ///< Set to true if the DNS options comes from --dhcp-option options
    std::vector<DnsDomain> search_domains; ///< List of global DNS search domains to use
    std::map<int, DnsServer> servers;      ///< List of DNS servers to use, according to the list of priority

  protected:
    /**
     *  Instantiate a new DnsServer object for a given DNS server priority
     *  and add it to the DnsOptions server list.
     *
     *  @param priority   Priority value for the new DnsServer setting
     *  @return A new instantiated DnsServer object
     */
    DnsServer &get_server(const int priority)
    {
        auto it = servers.insert(std::make_pair(priority, DnsServer())).first;
        return (*it).second;
    }
};

} // namespace openvpn
