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

#include <vector>
#include <cstdint>
#include <algorithm>
#include <sstream>

#include <openvpn/options/continuation.hpp>
#include <openvpn/client/dns_options.hpp>

#ifdef HAVE_JSON
#include <openvpn/common/jsonhelper.hpp>
#endif

namespace openvpn {

/**
 * @class DnsOptions
 * @brief All DNS options set with the --dns or --dhcp-option directive
 */
struct DnsOptionsParser : public DnsOptions
{
    DnsOptionsParser(const OptionList &opt, bool use_dhcp_search_domains_as_split_domains)
    {
        parse_dns_options(opt);
        parse_dhcp_options(opt, use_dhcp_search_domains_as_split_domains, !servers.empty());
        if (!parse_errors.empty())
        {
            OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, parse_errors);
        }
    }

    static int parse_priority(const std::string &prio_str)
    {
        const auto min_prio = std::numeric_limits<std::int8_t>::min();
        const auto max_prio = std::numeric_limits<std::int8_t>::max();

        int priority;
        if (!parse_number_validate<int>(prio_str, 4, min_prio, max_prio, &priority))
            OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server priority '" << prio_str << "' invalid");
        return priority;
    }

  protected:
    std::string parse_errors;

    void parse_dns_options(const OptionList &opt)
    {
        auto indices = opt.get_index_ptr("dns");
        if (indices == nullptr)
        {
            return;
        }

        for (const auto i : *indices)
        {
            try
            {
                const auto &o = opt[i];
                if (o.size() >= 3 && o.ref(1) == "search-domains")
                {
                    for (std::size_t j = 2; j < o.size(); j++)
                    {
                        search_domains.emplace_back(o.ref(j));
                    }
                }
                else if (o.size() >= 5 && o.ref(1) == "server")
                {
                    auto priority = parse_priority(o.ref(2));
                    auto &server = get_server(priority);

                    const auto &server_suboption = o.ref(3);
                    if (server_suboption == "address" && o.size() <= 12)
                    {
                        for (std::size_t j = 4; j < o.size(); j++)
                        {
                            try
                            {
                                server.addresses.emplace_back(DnsAddress(o.ref(j)));
                            }
                            catch (const openvpn::Exception &error)
                            {
                                OPENVPN_THROW_ARG1(option_error,
                                                   ERR_INVALID_OPTION_DNS,
                                                   "dns server " << priority << " error: " << error.what());
                            }
                        }
                    }
                    else if (server_suboption == "resolve-domains")
                    {
                        for (std::size_t j = 4; j < o.size(); j++)
                        {
                            server.domains.emplace_back(o.ref(j));
                        }
                    }
                    else if (server_suboption == "dnssec" && o.size() == 5)
                    {
                        try
                        {
                            server.parse_dnssec_value(o.ref(4));
                        }
                        catch (const openvpn::Exception &error)
                        {
                            OPENVPN_THROW_ARG1(option_error,
                                               ERR_INVALID_OPTION_DNS,
                                               "dns server " << priority << " error: " << error.what());
                        }
                    }
                    else if (server_suboption == "transport" && o.size() == 5)
                    {
                        try
                        {
                            server.parse_transport_value(o.ref(4));
                        }
                        catch (const openvpn::Exception &error)
                        {
                            OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " error: " << error.what());
                        }
                    }
                    else if (server_suboption == "sni" && o.size() == 5)
                    {
                        server.sni = o.ref(4);
                    }
                    else
                    {
                        OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns server " << priority << " option '" << server_suboption << "' unknown or too many parameters");
                    }
                }
                else
                {
                    OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, "dns option unknown or invalid number of parameters " << o.render(Option::RENDER_TRUNC_64 | Option::RENDER_BRACKET));
                }
            }
            catch (const std::exception &e)
            {
                parse_errors += "\n";
                parse_errors += e.what();
            }
        }

        // Check and remove servers without an address
        std::vector<int> remove_servers;
        for (const auto &[priority, server] : servers)
        {
            if (server.addresses.empty())
            {
                parse_errors += "\n";
                parse_errors += "dns server " + std::to_string(priority) + " does not have an address assigned";
                remove_servers.push_back(priority);
            }
        }
        for (const auto &prio : remove_servers)
        {
            servers.erase(prio);
        }

        // Clear search domains when no servers were configured
        if (servers.empty())
        {
            search_domains.clear();
        }
    }

    void parse_dhcp_options(const OptionList &opt, bool use_search_as_split_domains, bool ignore_values)
    {
        auto dhcp_map = opt.map().find("dhcp-option");
        if (dhcp_map == opt.map().end())
        {
            return;
        }

        // Example:
        //   [dhcp-option] [DNS] [172.16.0.23]
        //   [dhcp-option] [DOMAIN] [openvpn.net]
        //   [dhcp-option] [DOMAIN] [example.com]
        //   [dhcp-option] [DOMAIN] [foo1.com foo2.com foo3.com ...]
        //   [dhcp-option] [DOMAIN] [bar1.com] [bar2.com] [bar3.com] ...
        //   [dhcp-option] [ADAPTER_DOMAIN_SUFFIX] [mycompany.com]
        std::string adapter_domain_suffix;
        for (const auto &i : dhcp_map->second)
        {
            try
            {
                const Option &o = opt[i];
                const std::string &type = o.get(1, 64);
                if (type == "DNS" || type == "DNS6")
                {
                    o.exact_args(3);
                    try
                    {
                        if (!ignore_values)
                        {
                            auto &server = get_server(0);
                            server.addresses.emplace_back(DnsAddress(o.get(2, 256)));
                            from_dhcp_options = true;
                        }
                    }
                    catch (const IP::ip_exception &)
                    {
                        OPENVPN_THROW_ARG1(option_error, ERR_INVALID_OPTION_DNS, o.render(Option::RENDER_BRACKET) << " invalid address");
                    }
                    catch (const openvpn::Exception &error)
                    {
                        OPENVPN_THROW_ARG1(option_error,
                                           ERR_INVALID_OPTION_DNS,
                                           o.render(Option::RENDER_BRACKET) << "dhcp-option DNS error: " << error.what());
                    }
                }
                else if (type == "DOMAIN" || type == "DOMAIN-SEARCH")
                {
                    o.min_args(3);
                    for (size_t i = 2; i < o.size(); ++i)
                    {
                        using StrVec = std::vector<std::string>;
                        const StrVec domains = Split::by_space<StrVec, StandardLex, SpaceMatch, Split::NullLimit>(o.get(i, 256));
                        if (ignore_values)
                        {
                            continue;
                        }
                        for (const auto &domain : domains)
                        {
                            from_dhcp_options = true;
                            if (use_search_as_split_domains)
                            {
                                auto &server = get_server(0);
                                server.domains.emplace_back(domain);
                            }
                            else
                            {
                                search_domains.emplace_back(domain);
                            }
                        }
                    }
                }
                else if (type == "ADAPTER_DOMAIN_SUFFIX")
                {
                    o.exact_args(3);
                    if (!ignore_values)
                    {
                        adapter_domain_suffix = o.ref(2);
                        from_dhcp_options = true;
                    }
                }
            }
            catch (const std::exception &e)
            {
                parse_errors += "\n";
                parse_errors += e.what();
            }
        }

        if (!adapter_domain_suffix.empty())
        {
            search_domains.insert(search_domains.begin(), DnsDomain(std::move(adapter_domain_suffix)));
        }

        if (!ignore_values && !servers.empty() && servers[0].addresses.empty())
        {
            parse_errors += "\n";
            parse_errors += "dns server does not have an address assigned";
            servers.clear();
        }
    }
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
            const auto priority = DnsOptionsParser::parse_priority(opt.ref(2));
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
                const auto priority = DnsOptionsParser::parse_priority(pushed[i].ref(2));
                pushed_prios.emplace_back(priority);
            }
        }

        DnsFilter filter(std::move(pushed_prios));
        pushed.extend(config, &filter);
    }
};

} // namespace openvpn
