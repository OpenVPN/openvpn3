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
#include <cstdint>
#include <algorithm>
#include <sstream>

#include <openvpn/options/continuation.hpp>
#include <openvpn/common/hostport.hpp>
#include <openvpn/common/number.hpp>
#include <openvpn/common/jsonlib.hpp>
#include <openvpn/addr/ip.hpp>

#ifdef HAVE_JSON
#include <openvpn/common/jsonhelper.hpp>
#endif

namespace openvpn {

/**
 * @class DnsAddress
 * @brief A name server address and optional port
 */
struct DnsAddress
{
    /**
     * @brief Return string representation of the DnsAddress object
     *
     * @return std::string  the string representation generated
     */
    std::string to_string() const
    {
        std::ostringstream os;
        os << address.to_string();
        if (port)
        {
            os << " " << port;
        }
        return os.str();
    }

    void validate(const std::string &title) const
    {
        IP::Addr::validate(address.to_string(), title);
    }

#ifdef HAVE_JSON
    Json::Value to_json() const
    {
        Json::Value root(Json::objectValue);
        root["address"] = Json::Value(address.to_string());
        if (port)
        {
            root["port"] = Json::Value(port);
        }
        return root;
    }

    void from_json(const Json::Value &root, const std::string &title)
    {
        json::assert_dict(root, title);
        json::to_uint_optional(root, port, "port", 0u, title);

        std::string addr_str;
        json::to_string(root, addr_str, "address", title);
        address = IP::Addr::from_string(addr_str);
    }
#endif

    IP::Addr address;
    unsigned int port = 0;
};

/**
 * @class DnsDomain
 * @brief A DNS domain name
 */
struct DnsDomain
{
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
};

/**
 * @class DnsServer
 * @brief DNS settings for a name server
 */
struct DnsServer
{
    static std::int32_t parse_priority(const std::string &prio_str)
    {
        const auto min_prio = std::numeric_limits<std::int8_t>::min();
        const auto max_prio = std::numeric_limits<std::int8_t>::max();

        std::int32_t priority;
        if (!parse_number_validate<std::int32_t>(prio_str, 4, min_prio, max_prio, &priority))
            OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server priority '" << prio_str << "' invalid");
        return priority;
    }

    enum class Security
    {
        Unset,
        No,
        Yes,
        Optional
    };

    std::string dnssec_string(const Security dnssec) const
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

    enum class Transport
    {
        Unset,
        Plain,
        HTTPS,
        TLS
    };

    std::string transport_string(const Transport transport) const
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

    std::string to_string(const char *prefix = "") const
    {
        std::ostringstream os;
        os << prefix << "Addresses:" << std::endl;
        for (const auto &address : addresses)
        {
            os << prefix << "  " << address.to_string() << std::endl;
        }
        if (!domains.empty())
        {
            os << prefix << "Domains:" << std::endl;
            for (const auto &domain : domains)
            {
                os << prefix << "  " << domain.to_string() << std::endl;
            }
        }
        if (dnssec != Security::Unset)
        {
            os << prefix << "DNSSEC: " << dnssec_string(dnssec) << std::endl;
        }
        if (transport != Transport::Unset)
        {
            os << prefix << "Transport: " << transport_string(transport) << std::endl;
        }
        if (!sni.empty())
        {
            os << prefix << "SNI: " << sni << std::endl;
        }
        return os.str();
    }

#ifdef HAVE_JSON
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

    std::vector<DnsAddress> addresses;
    std::vector<DnsDomain> domains;
    Security dnssec = Security::Unset;
    Transport transport = Transport::Unset;
    std::string sni;
};

struct DnsOptionsMerger : public PushOptionsMerger
{
    using PriorityList = std::vector<std::int8_t>;

    struct DnsFilter : public OptionList::FilterBase
    {
        DnsFilter(PriorityList &&pushed_prios)
            : pushed_prios_(std::forward<PriorityList>(pushed_prios))
        {
        }

        bool filter(const Option &opt) override
        {
            if (opt.empty()
                || opt.size() < 3
                || opt.ref(0) != "dns"
                || opt.ref(1) != "server")
            {
                return true;
            }
            const auto priority = DnsServer::parse_priority(opt.ref(2));
            const auto it = std::find(pushed_prios_.begin(), pushed_prios_.end(), priority);

            // Filter out server option if an option with this priority was pushed
            return it == pushed_prios_.end() ? true : false;
        }

      protected:
        const PriorityList pushed_prios_;
    };

    void merge(OptionList &pushed, const OptionList &config) const override
    {
        PriorityList pushed_prios;

        auto indices = pushed.get_index_ptr("dns");
        if (indices)
        {
            for (const auto i : *indices)
            {
                if (pushed[i].size() < 3 || pushed[i].ref(1) != "server")
                    continue;
                const auto priority = DnsServer::parse_priority(pushed[i].ref(2));
                pushed_prios.emplace_back(priority);
            }
        }

        DnsFilter filter(std::move(pushed_prios));
        pushed.extend(config, &filter);
    }
};

/**
 * @class DnsOptions
 * @brief All options set with the --dns directive
 */
struct DnsOptions
{
    DnsOptions() = default;

    explicit DnsOptions(const OptionList &opt)
    {
        auto indices = opt.get_index_ptr("dns");
        if (indices == nullptr)
        {
            return;
        }

        for (const auto i : *indices)
        {
            const auto &o = opt[i];
            if (o.size() >= 3 && o.ref(1) == "search-domains")
            {
                for (std::size_t j = 2; j < o.size(); j++)
                {
                    search_domains.push_back({o.ref(j)});
                }
            }
            else if (o.size() >= 5 && o.ref(1) == "server")
            {
                auto priority = DnsServer::parse_priority(o.ref(2));
                auto &server = get_server(priority);

                if (o.ref(3) == "address" && o.size() <= 12)
                {
                    for (std::size_t j = 4; j < o.size(); j++)
                    {
                        IP::Addr addr;
                        unsigned int port = 0;
                        std::string addr_str = o.ref(j);

                        const bool v4_port_found = addr_str.find(':') != std::string::npos
                                                   && addr_str.find(':') == addr_str.rfind(':');

                        if (addr_str[0] == '[' || v4_port_found)
                        {
                            std::string port_str;
                            if (!HostPort::split_host_port(o.ref(j), addr_str, port_str, "", false, &port))
                            {
                                OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " invalid address: " << o.ref(j));
                            }
                        }

                        try
                        {
                            addr = IP::Addr(addr_str);
                        }
                        catch (const IP::ip_exception &)
                        {
                            OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " invalid address: " << o.ref(j));
                        }

                        server.addresses.push_back({addr, port});
                    }
                }
                else if (o.ref(3) == "resolve-domains")
                {
                    for (std::size_t j = 4; j < o.size(); j++)
                    {
                        server.domains.push_back({o.ref(j)});
                    }
                }
                else if (o.ref(3) == "dnssec" && o.size() == 5)
                {
                    if (o.ref(4) == "yes")
                    {
                        server.dnssec = DnsServer::Security::Yes;
                    }
                    else if (o.ref(4) == "no")
                    {
                        server.dnssec = DnsServer::Security::No;
                    }
                    else if (o.ref(4) == "optional")
                    {
                        server.dnssec = DnsServer::Security::Optional;
                    }
                    else
                    {
                        OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " dnssec setting '" << o.ref(4) << "' invalid");
                    }
                }
                else if (o.ref(3) == "transport" && o.size() == 5)
                {
                    if (o.ref(4) == "plain")
                    {
                        server.transport = DnsServer::Transport::Plain;
                    }
                    else if (o.ref(4) == "DoH")
                    {
                        server.transport = DnsServer::Transport::HTTPS;
                    }
                    else if (o.ref(4) == "DoT")
                    {
                        server.transport = DnsServer::Transport::TLS;
                    }
                    else
                    {
                        OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " transport '" << o.ref(4) << "' invalid");
                    }
                }
                else if (o.ref(3) == "sni" && o.size() == 5)
                {
                    server.sni = o.ref(4);
                }
                else
                {
                    OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " option '" << o.ref(3) << "' unknown or too many parameters");
                }
            }
            else
            {
                OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns option unknown or invalid number of parameters " << o.render(Option::RENDER_TRUNC_64 | Option::RENDER_BRACKET));
            }
        }

        for (const auto &[priority, server] : servers)
        {
            if (server.addresses.empty())
            {
                OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " does not have an address assigned");
            }
        }
    }

    std::string to_string() const
    {
        std::ostringstream os;
        if (!servers.empty())
        {
            os << "DNS Servers:" << std::endl;
            for (const auto &elem : servers)
            {
                os << "  Priority: " << elem.first << std::endl;
                os << elem.second.to_string("  ");
            }
        }
        if (!search_domains.empty())
        {
            os << "DNS Search Domains:" << std::endl;
            for (const auto &domain : search_domains)
            {
                os << "  " << domain.to_string() << std::endl;
            }
        }
        return os.str();
    }

#ifdef HAVE_JSON
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
        return root;
    }

    void from_json(const Json::Value &root, const std::string &title)
    {
        json::assert_dict(root, title);
        json::assert_dict(root["servers"], title);
        for (const auto &prio : root["servers"].getMemberNames())
        {
            DnsServer server;
            server.from_json(root["servers"][prio], title);
            servers[std::stoi(prio)] = std::move(server);
        }
        json::to_vector(root, search_domains, "search_domains", title);
    }
#endif

    std::vector<DnsDomain> search_domains;
    std::map<std::int32_t, DnsServer> servers;

  protected:
    DnsServer &get_server(const std::int32_t priority)
    {
        auto it = servers.insert(std::make_pair(priority, DnsServer())).first;
        return (*it).second;
    }
};

} // namespace openvpn
