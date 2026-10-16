//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012- OpenVPN Inc.
//
//    SPDX-License-Identifier: MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception
//

// OpenVPN agent for Windows

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <utility>
#include <map>
#include <functional>
#include <set>
#include <vector>

#include <openvpn/io/io.hpp>

#include <openvpn/common/stringize.hpp>
// VERSION version can be passed on build command line
#ifdef VERSION
#define HTTP_SERVER_VERSION OPENVPN_STRINGIZE(VERSION)
#else
#define HTTP_SERVER_VERSION "0.1.0"
#endif
// OVPNAGENT_NAME can be passed on build command line.
// Customized agent name is needed with purpose to install
// few app with agents on one OS (e.g OC 3.0 and PT)
#ifdef OVPNAGENT_NAME
#define OVPNAGENT_NAME_STRING OPENVPN_STRINGIZE(OVPNAGENT_NAME)
#else
#define OVPNAGENT_NAME_STRING "ovpnagent"
#endif

#include <openvpn/log/logbase.hpp>

#include <openvpn/common/exception.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/string.hpp>
#include <openvpn/common/rc.hpp>
#include <openvpn/common/path.hpp>
#include <openvpn/common/file.hpp>
#include <openvpn/common/splitlines.hpp>
#include <openvpn/common/wstring.hpp>
#include <openvpn/log/logbasesimple.hpp>
#include <openvpn/buffer/buflist.hpp>
#include <openvpn/buffer/bufhex.hpp>
#include <openvpn/init/initprocess.hpp>
#include <openvpn/ssl/sslchoose.hpp>
#include <openvpn/ws/httpserv.hpp>
#include <openvpn/win/winerr.hpp>
#include <openvpn/client/win/agentconfig.hpp>
#include <openvpn/win/scoped_handle.hpp>
#include <openvpn/win/winsvc.hpp>
#include <openvpn/win/logfile.hpp>
#include <openvpn/tun/win/client/tunsetup.hpp>
#include <openvpn/win/npinfo.hpp>
#include <openvpn/win/handlecomm.hpp>
#include <openvpn/win/cancelable_handle.hpp>
#include <openvpn/addr/route.hpp>

void log_version()
{
    OPENVPN_LOG("OpenVPN Agent " HTTP_SERVER_VERSION " [" SSL_LIB_NAME "]");
}

using namespace openvpn;

struct MyConfig
{
    MyConfig()
    {
        pipe_name = Agent::named_pipe_path();
        server_exe = Win::module_name_utf8();
        n_pipe_instances = 4;
    }

    std::string pipe_name;
    std::string server_exe;
    unsigned int n_pipe_instances;
};

class MySessionStats : public SessionStats
{
  public:
    typedef RCPtr<MySessionStats> Ptr;

    void error(const size_t err_type, const std::string *text = nullptr) override
    {
        OPENVPN_LOG(openvpn::Error::name(err_type));
    }

    std::string dump() const
    {
        std::ostringstream os;
        os << "OpenVPN Agent Stats\n";
        return os.str();
    }
};

// State of a single tunnel, owned by the client process that requested it.
// Sessions are keyed by the client PID, so that several clients can keep
// their tunnels up at the same time.
class TunSession : public RC<thread_unsafe_refcount>
{
  public:
    typedef RCPtr<TunSession> Ptr;

    // called when the client process exits or signals the destroy event
    typedef std::function<void(TunSession &, const char *reason)> CloseHandler;

    TunSession(openvpn_io::io_context &io_context,
               const DWORD pid,
               CloseHandler close_handler)
        : client_process(io_context),
          client_confirm_event(io_context),
          client_destroy_event(io_context),
          io_context_(io_context),
          pid_(pid),
          close_handler_(std::move(close_handler))
    {
    }

    DWORD pid() const
    {
        return pid_;
    }

    // index of the VPN interface, DWORD(-1) if there is none yet
    DWORD vpn_interface() const
    {
        return vpn_interface_index;
    }

    // true if the tunnel is up and has taken over the default route
    bool redirects_gateway() const
    {
        return redirects_gateway_;
    }

    // true if the tunnel is up and needs the block-ipv6 routes
    bool blocks_ipv6() const
    {
        return blocks_ipv6_;
    }

    // routes into the tunnel, empty if it is not up
    const std::vector<IP::Route> &routes() const
    {
        return routes_;
    }

    // the tunnel of another client came up or went down
    void add_other_vpn_interface(const DWORD itf_index, std::ostream &os)
    {
        if (tun)
            tun->add_other_vpn_interface(itf_index, os);
    }

    void remove_other_vpn_interface(const DWORD itf_index, std::ostream &os)
    {
        if (tun)
            tun->remove_other_vpn_interface(itf_index, os);
    }

    Win::ScopedHANDLE tun_get_handle(std::ostream &os,
                                     const TunWin::Type tun_type,
                                     bool allow_local_dns_resolvers)
    {
        if (!tun)
            tun.reset(new TunWin::Setup(io_context_, tun_type, allow_local_dns_resolvers));
        Win::ScopedHANDLE th(tun->get_handle(os));
        // the adapter is ours from now on, so other tunnels must skip it too
        vpn_interface_index = tun->get_adapter_state().index;
        return th;
    }

    TunWin::Util::TapNameGuidPair get_adapter_state()
    {
        return tun->get_adapter_state();
    }

    Win::ScopedHANDLE establish_tun(const TunBuilderCapture &tbc,
                                    const std::wstring &openvpn_app_path,
                                    Stop *stop,
                                    std::ostream &os,
                                    TunWin::Type tun_type,
                                    bool allow_local_dns_resolvers,
                                    TunWin::Util::TapNameGuidPair tap,
                                    std::set<DWORD> other_vpn_interfaces)
    {
        if (!tun)
            tun.reset(new TunWin::Setup(io_context_, tun_type, allow_local_dns_resolvers));

        if ((tun_type == TunWin::OvpnDco) && (tap.index != DWORD(-1)))
            tun->set_adapter_state(tap);

        tun->set_process_id(pid_);
        tun->set_other_vpn_interfaces(std::move(other_vpn_interfaces), os);
        // shared by all tunnels, managed by the listener
        tun->set_block_ipv6_routes(false);
        auto th = tun->establish(tbc, openvpn_app_path, stop, os, ring_buffer);
        // store VPN interface index to be able to exclude it
        // when next time adding bypass route
        vpn_interface_index = tun->vpn_interface_index();
        redirects_gateway_ = tbc.reroute_gw.ipv4 || tbc.reroute_gw.ipv6;
        blocks_ipv6_ = tbc.block_ipv6;
        routes_.clear();
        for (const auto &r : tbc.add_routes)
            routes_.emplace_back(IP::Addr::from_string(r.address), r.prefix_length);
        return Win::ScopedHANDLE(th);
    }

    // Undo the tun setup. The client process handle and the bypass
    // routes are kept, so that a tunnel can be set up again by the
    // same client and the failsafe keeps watching the client.
    // Return true if we did any work.
    bool destroy_tun(std::ostream &os)
    {
        bool ret = false;
        try
        {
            // close the remote tap handle in the client process
            if (client_process.is_open() && !remote_tap_handle_hex.empty())
            {
                ret = true;
                const HANDLE remote_tap_handle = BufHex::parse<HANDLE>(remote_tap_handle_hex, "remote TAP handle");
                Win::ScopedHANDLE local_tap_handle; // dummy handle, immediately closed after duplication
                if (::DuplicateHandle(client_process.native_handle(),
                                      remote_tap_handle,
                                      GetCurrentProcess(),
                                      local_tap_handle.ref(),
                                      0,
                                      FALSE,
                                      DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
                {
                    os << "destroy_tun: no client confirm, DuplicateHandle (close) succeeded\n";
                }
                else
                {
                    const Win::LastError err;
                    os << "destroy_tun: no client confirm, DuplicateHandle (close) failed: " << err.message() << "\n";
                }
            }
        }
        catch (const std::exception &e)
        {
            os << "destroy_tun: exception in remote tap handle close: " << e.what() << "\n";
        }

        try
        {
            ring_buffer.reset();

            // undo the effects of establish_tun
            if (tun)
            {
                ret = true;
                tun->destroy(os);
            }
        }
        catch (const std::exception &e)
        {
            os << "destroy_tun: exception in tun teardown: " << e.what() << "\n";
        }

        try
        {
            tun.reset();
            remote_tap_handle_hex.clear();
            client_confirm_event.close();
            client_destroy_event.cancel_and_close();
        }
        catch (const std::exception &e)
        {
            os << "destroy_tun: exception in cleanup: " << e.what() << "\n";
        }
        vpn_interface_index = DWORD(-1);
        redirects_gateway_ = false;
        blocks_ipv6_ = false;
        routes_.clear();
        return ret;
    }

    void remove_bypass_routes(std::ostream &os)
    {
        remove_cmds_bypass_hosts.execute(os);
        remove_cmds_bypass_hosts.clear();
    }

    void close_client_process()
    {
        client_process.close();
    }

    void set_client_process(Win::ScopedHANDLE &&proc)
    {
        client_process.close();
        client_process.assign(proc.release());

        // special failsafe to destroy tun in case client crashes without closing it
        client_process.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                                  {
	if (!error)
	  self->close_handler_(*self, "failsafe"); });
    }

    void set_client_confirm_event(const std::string &confirm_handle_hex)
    {
        client_confirm_event.close();

        const HANDLE remote_event = BufHex::parse<HANDLE>(confirm_handle_hex, "confirm event handle");
        HANDLE event_handle;
        if (!::DuplicateHandle(get_client_process(),
                               remote_event,
                               GetCurrentProcess(),
                               &event_handle,
                               0,
                               FALSE,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
        {
            const Win::LastError err;
            OPENVPN_THROW_EXCEPTION("set_client_confirm_event: DuplicateHandle failed: " << err.message());
        }
        client_confirm_event.assign(event_handle);

        // Check if the event is okay
        {
            const DWORD status = ::WaitForSingleObject(client_confirm_event.native_handle(), 0);
            const Win::LastError err;
            switch (status)
            {
            case WAIT_OBJECT_0: // acceptable status
            case WAIT_TIMEOUT:  // acceptable status
                break;
            case WAIT_ABANDONED:
                throw Exception("set_client_confirm_event: confirm event is abandoned");
            default:
                OPENVPN_THROW_EXCEPTION("set_client_confirm_event: WaitForSingleObject failed: " << err.message());
            }
        }

        // When the client signals the client_confirm event, it means
        // that the client has taken ownership of the TAP device HANDLE,
        // so we locally release ownership by clearing remote_tap_handle_hex,
        // effectively preventing the cross-process release of TAP device
        // HANDLE in destroy_tun() above.
        client_confirm_event.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                                        {
	if (!error)
	  {
	    self->remote_tap_handle_hex.clear();
	    OPENVPN_LOG_STRING("TUN CONFIRM pid=" + std::to_string(self->pid_) + "\n");
	  } });
    }

    void set_client_destroy_event(const std::string &event_handle_hex)
    {
        client_destroy_event.cancel_and_close();

        // Move the remote event HANDLE (already duplicated in remote process)
        // to local process.
        const HANDLE remote_event = BufHex::parse<HANDLE>(event_handle_hex, "destroy event handle");
        HANDLE event_handle;
        if (!::DuplicateHandle(get_client_process(),
                               remote_event,
                               GetCurrentProcess(),
                               &event_handle,
                               0,
                               FALSE,
                               DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE))
        {
            const Win::LastError err;
            OPENVPN_THROW_EXCEPTION("set_client_destroy_event: DuplicateHandle failed: " << err.message());
        }
        client_destroy_event.assign(event_handle);

        // Check if the event is already signaled, or has some other error
        client_destroy_event.check_is_already_signalled();

        // normal event-based tun close processing
        client_destroy_event.async_wait([self = Ptr(this)](const openvpn_io::error_code &error)
                                        {
	if (!error)
	  self->close_handler_(*self, "event"); });
    }

    HANDLE get_client_process()
    {
        if (!client_process.is_open())
            throw Exception("no client process");
        return client_process.native_handle();
    }

    void set_remote_tap_handle_hex(const HANDLE tap_handle)
    {
        remote_tap_handle_hex = Win::HandleComm::send_handle(tap_handle, get_client_process());
    }

    const std::string &get_remote_tap_handle_hex()
    {
        return remote_tap_handle_hex;
    }

    void assign_ring_buffer(TunWin::RingBuffer *ring_buffer_arg)
    {
        ring_buffer.reset(ring_buffer_arg);
    }

    void add_bypass_route(const std::string &host, bool ipv6, std::set<DWORD> vpn_interfaces)
    {
        std::ostringstream os;
        remove_bypass_routes(os);

        ActionList add_cmds;
        // we might have broken VPN connection up, so we must
        // exclude VPN interface whe searching for the best gateway,
        // and so the interfaces of the other tunnels
        if (vpn_interface_index != DWORD(-1))
            vpn_interfaces.insert(vpn_interface_index);
        ADDRESS_FAMILY af = ipv6 ? AF_INET6 : AF_INET;
        const TunWin::Util::BestGateway gw{af, host, vpn_interfaces};
        TunWin::Setup::add_bypass_route(gw, host, ipv6, add_cmds, remove_cmds_bypass_hosts);
        add_cmds.execute(os);

        OPENVPN_LOG(os.str());
    }

  private:
    TunWin::Setup::Ptr tun;
    TunWin::RingBuffer::Ptr ring_buffer;
    ActionList remove_cmds_bypass_hosts;
    openvpn_io::windows::object_handle client_process;
    openvpn_io::windows::object_handle client_confirm_event;
    CancelableHandle client_destroy_event;
    std::string remote_tap_handle_hex;
    openvpn_io::io_context &io_context_;
    const DWORD pid_;
    CloseHandler close_handler_;

    // with persist tunnel and redirect-gw we must exclude
    // VPN interface when searching for best gateway when
    // adding bypass route for the next remote
    DWORD vpn_interface_index = DWORD(-1);

    bool redirects_gateway_ = false;
    bool blocks_ipv6_ = false;
    std::vector<IP::Route> routes_;
};

class MyListener : public WS::Server::Listener
{
  public:
    typedef RCPtr<MyListener> Ptr;

    MyListener(const MyConfig &config_arg,
               openvpn_io::io_context &io_context,
               const WS::Server::Config::Ptr &hconf,
               const Listen::List &listen_list,
               const WS::Server::Listener::Client::Factory::Ptr &client_factory)
        : WS::Server::Listener(io_context, hconf, listen_list, client_factory),
          config(config_arg),
          io_context_(io_context)
    {
    }

    // return the session of the given client, create it if needed
    TunSession::Ptr get_session(const DWORD pid)
    {
        TunSession::Ptr &session = sessions[pid];
        if (!session)
        {
            session.reset(new TunSession(io_context_, pid, [this](TunSession &s, const char *reason)
                                         { close_session(s, reason); }));
            OPENVPN_LOG("new session pid=" << pid << ", sessions=" << sessions.size());
        }
        return session;
    }

    // VPN interfaces of all sessions but the given one
    std::set<DWORD> other_vpn_interfaces(const DWORD pid) const
    {
        std::set<DWORD> ret;
        for (const auto &[session_pid, session] : sessions)
            if (session_pid != pid && session->vpn_interface() != DWORD(-1))
                ret.insert(session->vpn_interface());
        return ret;
    }

    // the session of another client whose tunnel redirects the default gateway
    TunSession::Ptr gateway_owner(const DWORD pid) const
    {
        for (const auto &[session_pid, session] : sessions)
            if (session_pid != pid && session->redirects_gateway())
                return session;
        return TunSession::Ptr();
    }

    TunSession::Ptr find_session(const DWORD pid) const
    {
        const auto it = sessions.find(pid);
        if (it == sessions.end())
            return TunSession::Ptr();
        return it->second;
    }

    // Tell the other sessions about the VPN interface of a session, so that
    // their WFP filters don't block it and their bypass routes avoid it.
    void announce_vpn_interface(const DWORD pid, const DWORD itf_index, std::ostream &os)
    {
        if (itf_index == DWORD(-1))
            return;
        for (const auto &[session_pid, session] : sessions)
            if (session_pid != pid)
                session->add_other_vpn_interface(itf_index, os);
    }

    void withdraw_vpn_interface(const DWORD pid, const DWORD itf_index, std::ostream &os)
    {
        if (itf_index == DWORD(-1))
            return;
        for (const auto &[session_pid, session] : sessions)
            if (session_pid != pid)
                session->remove_other_vpn_interface(itf_index, os);
    }

    // The block-ipv6 routes are the same for all tunnels: add them for the
    // first session that needs them and remove them with the last one.
    void acquire_block_ipv6(std::ostream &os)
    {
        if (block_ipv6_users++ == 0)
        {
            ActionList add_cmds;
            TunWin::Setup::add_block_ipv6_routes(add_cmds, remove_cmds_block_ipv6);
            add_cmds.execute(os);
        }
    }

    void release_block_ipv6(std::ostream &os)
    {
        if (block_ipv6_users > 0 && --block_ipv6_users == 0)
        {
            remove_cmds_block_ipv6.execute(os);
            remove_cmds_block_ipv6.clear();
        }
    }

    // undo the tun setup of a session, including what is shared with the others
    bool destroy_session_tun(TunSession &session, std::ostream &os)
    {
        const DWORD itf_index = session.vpn_interface();
        const bool blocked_ipv6 = session.blocks_ipv6();
        const bool ret = session.destroy_tun(os);
        withdraw_vpn_interface(session.pid(), itf_index, os);
        if (blocked_ipv6)
            release_block_ipv6(os);
        return ret;
    }

    // Compare routes with those of the other tunnels. Identical routes are
    // conflicts: destinations in them may go through either tunnel. Nested
    // routes are just overlaps, the more specific route always wins.
    void route_conflicts(const DWORD pid,
                         const std::vector<IP::Route> &routes,
                         std::vector<std::string> &conflicts,
                         std::vector<std::string> &overlaps) const
    {
        for (const auto &[session_pid, session] : sessions)
        {
            if (session_pid == pid)
                continue;
            const std::string owner = " of the tunnel of process " + std::to_string(session_pid);
            for (const IP::Route &r : routes)
                for (const IP::Route &o : session->routes())
                {
                    if (r == o)
                        conflicts.push_back(r.to_string() + " overlaps " + o.to_string() + owner);
                    else if (r.contains(o))
                        overlaps.push_back(r.to_string() + " contains " + o.to_string() + owner);
                    else if (o.contains(r))
                        overlaps.push_back(r.to_string() + " is inside " + o.to_string() + owner);
                }
        }
    }

    // tear down everything the session has set up and forget it
    void close_session(TunSession &session, const char *reason)
    {
        // keep the session alive until we're done with it
        const TunSession::Ptr hold(&session);

        std::ostringstream os;
        session.remove_bypass_routes(os);
        destroy_session_tun(session, os);
        session.close_client_process();

        const auto it = sessions.find(session.pid());
        if (it != sessions.end() && it->second == hold)
            sessions.erase(it);

        OPENVPN_LOG_NTNL("SESSION CLOSE (" << reason << ") pid=" << session.pid()
                                           << ", sessions=" << sessions.size() << '\n'
                                           << os.str());
    }

    void close_all_sessions(const char *reason)
    {
        // close_session() modifies the map, so iterate over a copy
        const auto all = sessions;
        for (const auto &e : all)
            close_session(*e.second, reason);
    }

#ifdef OPENVPN_AGENT_START_PROCESS
    void start_openvpn_process(HANDLE client_pipe,
                               const std::string &config_file,
                               const std::string &config_dir,
                               const std::string &exit_event_name,
                               const std::string &management_host,
                               const std::string &management_password,
                               const int management_port,
                               const std::string &log,
                               const bool log_append)
    {
        // Only needed by /start, so that the agent can run without it for
        // clients which start their own process
        const std::string omiclient_exe = Win::omiclient_path();

        // impersonate pipe client
        Win::NamedPipeImpersonate impersonate{client_pipe};

        {
            // create primary token from impersonation token
            HANDLE imp_token = NULL, pri_token = NULL;
            BOOL res = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, FALSE, &imp_token);
            if (res == 0)
            {
                const openvpn_io::error_code err(::GetLastError(), openvpn_io::error::get_system_category());
                OPENVPN_THROW_EXCEPTION("failed to open thread token: " << err.message());
            }
            res = DuplicateTokenEx(imp_token, 0, NULL, SECURITY_IMPERSONATION_LEVEL::SecurityAnonymous, TokenPrimary, &pri_token);
            if (res == 0)
            {
                const openvpn_io::error_code err(::GetLastError(), openvpn_io::error::get_system_category());
                OPENVPN_THROW_EXCEPTION("failed to duplicate token: " << err.message());
            }

            // create pipe which is used to write password to openvpn process's stdin
            HANDLE stdin_read = NULL, stdin_write = NULL;
            SECURITY_ATTRIBUTES inheritable = {sizeof(inheritable), NULL, TRUE};
            if (!CreatePipe(&stdin_read, &stdin_write, &inheritable, 0)
                || !SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0))
            {
                const openvpn_io::error_code err(::GetLastError(), openvpn_io::error::get_system_category());
                OPENVPN_THROW_EXCEPTION("failed to set up pipe: " << err.message());
            }

            // create command line for openvpn process
            std::ostringstream ss;
            ss << "client --config \"" << config_dir << "\\" << config_file << "\" --exit-event-name "
               << exit_event_name << " --auth-retry interact --management " << management_host << " "
               << management_port << " stdin --management-query-passwords --management-hold "
               << "--log"
               << (log_append ? "-append \"" : " \"") << log << "\"";
            std::string cmd = ss.str();
            std::unique_ptr<char[]> buf(new char[cmd.length() + 1]);
            strcpy(buf.get(), cmd.c_str());

            // OPENVPN_LOG("Launching omiclient: " << omiclient_exe.c_str() << " " << buf.get());

            STARTUPINFO startup_info = {0};
            startup_info.cb = sizeof(startup_info);
            startup_info.dwFlags = STARTF_USESTDHANDLES;
            startup_info.hStdInput = stdin_read;

            // create openvpn process
            PROCESS_INFORMATION proc_info;
            ZeroMemory(&proc_info, sizeof(proc_info));
            res = CreateProcessAsUser(pri_token,
                                      omiclient_exe.c_str(),
                                      buf.get(),
                                      NULL,
                                      NULL,
                                      TRUE,
                                      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                                      0,
                                      0,
                                      &startup_info,
                                      &proc_info);
            if (res == 0)
            {
                const openvpn_io::error_code err(::GetLastError(), openvpn_io::error::get_system_category());
                OPENVPN_THROW_EXCEPTION("failed to create openvpn process: " << err.message());
            }
            CloseHandle(proc_info.hProcess);
            CloseHandle(proc_info.hThread);

            // write management password to process's stdin
            DWORD written;
            if (!is_safe_conversion<DWORD>(management_password.length()))
                return;
            WriteFile(stdin_write, management_password.c_str(), static_cast<DWORD>(management_password.length()), &written, NULL);
        }
    }
#endif

    const MyConfig &config;

  private:
    bool allow_client(AsioPolySock::Base &sock) override
    {
        AsioPolySock::NamedPipe *np = dynamic_cast<AsioPolySock::NamedPipe *>(&sock);
        if (np)
        {
            Win::NamedPipePeerInfoClient npinfo(np->handle.native_handle());
            const std::string client_exe = wstring::to_utf8(npinfo.exe_path);
            OPENVPN_LOG("connection from " << client_exe);
            if (Agent::valid_pipe(client_exe, config.server_exe))
                return true;
            OPENVPN_LOG(client_exe << " not recognized as a valid client");
        }
        else
            OPENVPN_LOG("only named pipe clients are allowed");
        return false;
    }

    std::map<DWORD, TunSession::Ptr> sessions;
    openvpn_io::io_context &io_context_;

    // sessions with block-ipv6 and how to remove its routes
    unsigned int block_ipv6_users = 0;
    ActionList remove_cmds_block_ipv6;
};

class MyClientInstance : public WS::Server::Listener::Client
{
  public:
    typedef RCPtr<MyClientInstance> Ptr;

    MyClientInstance(WS::Server::Listener::Client::Initializer &ci)
        : WS::Server::Listener::Client(ci)
    {
    }

    virtual ~MyClientInstance() = default;

  private:
    void generate_reply(const Json::Value &jout)
    {
        out = buf_from_string(jout.toStyledString());

        WS::Server::ContentInfo ci;
        ci.http_status = HTTP::Status::OK;
        ci.type = "application/json";
        ci.length = out->size();
        ci.keepalive = keepalive_request();
        generate_reply_headers(ci);
    }

    void http_request_received() override
    {
        // alloc output buffer
        std::ostringstream os;
        DWORD client_pid = 0;

        try
        {
            const HANDLE client_pipe = get_client_pipe();
            client_pid = get_client_pid(client_pipe);
            const std::wstring client_exe = get_client_exe(client_pipe);

            const HTTP::Request &req = request();
            OPENVPN_LOG("HTTP request received from " << sock->remote_endpoint_str() << '\n'
                                                      << req.to_string());

            // get content-type
            const std::string content_type = req.headers.get_value_trim("content-type");

            if (req.method == "POST")
            {
                // verify correct content-type
                if (string::strcasecmp(content_type, "application/json"))
                    throw Exception("bad content-type");

                // parse the json dict
                const Json::Value root = json::parse(in.to_string(), "JSON request");
                if (!root.isObject())
                    throw Exception("json parse error: top level json object is not a dictionary");

                if (req.uri == "/tun-open")
                {
                    const TunSession::Ptr session = parent()->get_session(client_pid);

                    // destroy previous instance of this client
                    if (parent()->destroy_session_tun(*session, os))
                    {
                        os << "Destroyed previous TAP instance\n";
                        ::Sleep(1000);
                    }

                    {
                        // remember the client process that sent the request
                        ULONG pid = json::get_uint_optional(root, "pid", 0);
                        const std::string confirm_event_hex = json::get_string(root, "confirm_event");
                        const std::string destroy_event_hex = json::get_string(root, "destroy_event");

                        Win::NamedPipeImpersonate impersonate(client_pipe);

                        session->set_client_process(get_client_process(client_pipe, pid));
                        session->set_client_confirm_event(confirm_event_hex);
                        session->set_client_destroy_event(destroy_event_hex);
                    }

                    bool allow_local_dns_resolvers = json::get_bool_optional(root, "allow_local_dns_resolvers");
                    Win::ScopedHANDLE th(session->tun_get_handle(os, TunWin::OvpnDco, allow_local_dns_resolvers));
                    {
                        // duplicate the TAP handle into the client process
                        Win::NamedPipeImpersonate impersonate(client_pipe);
                        session->set_remote_tap_handle_hex(th());
                    }

                    // build JSON return dictionary
                    const std::string log_txt = string::remove_blanks(os.str());
                    Json::Value jout(Json::objectValue);
                    jout["log_txt"] = log_txt;
                    jout["tap_handle_hex"] = session->get_remote_tap_handle_hex();

                    auto tap = session->get_adapter_state();
                    jout["adapter_guid"] = tap.guid;
                    jout["adapter_index"] = Json::Int(tap.index);
                    jout["adapter_name"] = tap.name;

                    OPENVPN_LOG_NTNL("TUN SETUP\n"
                                     << log_txt);

                    generate_reply(jout);
                }
                else if (req.uri == "/tun-setup")
                {
                    // get PID
                    ULONG pid = json::get_uint_optional(root, "pid", 0);

                    TunWin::Type tun_type;
                    switch (json::get_int_optional(root, "tun_type", TunWin::TapWindows6))
                    {
                    case TunWin::Wintun:
                        tun_type = TunWin::Wintun;
                        break;
                    case TunWin::OvpnDco:
                        tun_type = TunWin::OvpnDco;
                        break;
                    case TunWin::TapWindows6:
                    default:
                        tun_type = TunWin::TapWindows6;
                        break;
                    }

                    bool allow_local_dns_resolvers = json::get_bool_optional(root, "allow_local_dns_resolvers");
                    // parse JSON data into a TunBuilderCapture object
                    TunBuilderCapture::Ptr tbc = TunBuilderCapture::from_json(json::get_dict(root, "tun", false));
                    tbc->validate();

                    // Only one tunnel can be the default route. Pushed options are
                    // only known here, so this is the place to refuse a second one.
                    if (tbc->reroute_gw.ipv4 || tbc->reroute_gw.ipv6)
                    {
                        if (const TunSession::Ptr owner = parent()->gateway_owner(client_pid))
                            throw Exception("redirect-gateway: the default gateway is already redirected by the tunnel of process "
                                            + std::to_string(owner->pid()));
                    }

                    const TunSession::Ptr session = parent()->get_session(client_pid);

                    // destroy previous instance of this client
                    if (tun_type != TunWin::OvpnDco && parent()->destroy_session_tun(*session, os))
                    {
                        os << "Destroyed previous TAP instance\n";
                        ::Sleep(1000);
                    }

                    // pre-establish impersonation
                    {
                        Win::NamedPipeImpersonate impersonate(client_pipe);

                        // remember the client process that sent the request
                        session->set_client_process(get_client_process(client_pipe, pid));

                        // save destroy event
                        const std::string destroy_event_hex = json::get_string(root, "destroy_event");
                        session->set_client_destroy_event(destroy_event_hex);

                        if (tun_type != TunWin::OvpnDco)
                        {
                            // get remote event handle for tun object confirmation
                            const std::string confirm_event_hex = json::get_string(root, "confirm_event");

                            // save the confirm event
                            session->set_client_confirm_event(confirm_event_hex);
                        }
                    }

                    if (tun_type == TunWin::Wintun)
                    {
                        session->assign_ring_buffer(new TunWin::RingBuffer(io_context,
                                                                           session->get_client_process(),
                                                                           json::get_string(root, "send_ring_hmem"),
                                                                           json::get_string(root, "receive_ring_hmem"),
                                                                           json::get_string(root, "send_ring_tail_moved"),
                                                                           json::get_string(root, "receive_ring_tail_moved")));
                    }

                    TunWin::Util::TapNameGuidPair tap;
                    if (tun_type == TunWin::OvpnDco)
                    {
                        tap.guid = json::get_string(root, "adapter_guid");
                        tap.index = (DWORD)json::get_int(root, "adapter_index");
                        tap.name = json::get_string(root, "adapter_name");
                    }

                    // establish the tun setup object
                    Win::ScopedHANDLE tap_handle(session->establish_tun(*tbc, client_exe, nullptr, os, tun_type, allow_local_dns_resolvers, tap, parent()->other_vpn_interfaces(client_pid)));

                    // post-establish impersonation
                    {
                        Win::NamedPipeImpersonate impersonate(client_pipe);

                        // duplicate the TAP handle into the client process
                        session->set_remote_tap_handle_hex(tap_handle());
                    }

                    parent()->announce_vpn_interface(client_pid, session->vpn_interface(), os);
                    if (session->blocks_ipv6())
                        parent()->acquire_block_ipv6(os);

                    // The client shows conflicts to the user, see "ROUTE CONFLICT"
                    // in the GUI; overlaps are only logged.
                    std::vector<std::string> conflicts, overlaps;
                    parent()->route_conflicts(client_pid, session->routes(), conflicts, overlaps);
                    const size_t max_lines = 10;
                    for (size_t i = 0; i < conflicts.size() && i < max_lines; ++i)
                        os << "ROUTE CONFLICT: " << conflicts[i] << "\n";
                    if (conflicts.size() > max_lines)
                        os << "ROUTE CONFLICT: " << (conflicts.size() - max_lines) << " more\n";
                    for (size_t i = 0; i < overlaps.size() && i < max_lines; ++i)
                        os << "ROUTE OVERLAP: " << overlaps[i] << "\n";
                    if (overlaps.size() > max_lines)
                        os << "ROUTE OVERLAP: " << (overlaps.size() - max_lines) << " more\n";

                    // build JSON return dictionary
                    const std::string log_txt = string::remove_blanks(os.str());
                    Json::Value jout(Json::objectValue);
                    jout["log_txt"] = log_txt;
                    jout["tap_handle_hex"] = session->get_remote_tap_handle_hex();
                    OPENVPN_LOG_NTNL("TUN SETUP\n"
                                     << log_txt);

                    generate_reply(jout);
                }
                else if (req.uri == "/add-bypass-route")
                {
                    ULONG pid = json::get_uint_optional(root, "pid", 0);
                    bool ipv6 = json::get_bool(root, "ipv6");
                    const std::string host = json::get_string(root, "host");

                    const TunSession::Ptr session = parent()->get_session(client_pid);

                    // pre-establish impersonation
                    {
                        Win::NamedPipeImpersonate impersonate(client_pipe);

                        // remember the client process that sent the request
                        session->set_client_process(get_client_process(client_pipe, pid));
                    }

                    session->add_bypass_route(host, ipv6, parent()->other_vpn_interfaces(client_pid));

                    Json::Value jout(Json::objectValue);

                    generate_reply(jout);
                }
#ifdef OPENVPN_AGENT_START_PROCESS
                else if (req.uri == "/start")
                {
                    const std::string config_file = json::get_string(root, "config_file");
                    const std::string config_dir = json::get_string(root, "config_dir");
                    const std::string exit_event_name = json::get_string(root, "exit_event_name");
                    const std::string management_host = json::get_string(root, "management_host");
                    const std::string management_password = json::get_string(root, "management_password") + "\n";
                    const int management_port = json::get_int(root, "management_port");
                    const std::string log = json::get_string(root, "log");
                    const bool log_append = json::get_int(root, "log-append") == 1;

                    parent()->start_openvpn_process(client_pipe,
                                                    config_file,
                                                    config_dir,
                                                    exit_event_name,
                                                    management_host,
                                                    management_password,
                                                    management_port,
                                                    log,
                                                    log_append);

                    Json::Value jout(Json::objectValue);
                    generate_reply(jout);
                }
#endif
                else
                {
                    OPENVPN_LOG("PAGE NOT FOUND");
                    out = buf_from_string("page not found\n");
                    WS::Server::ContentInfo ci;
                    ci.http_status = HTTP::Status::NotFound;
                    ci.type = "text/plain";
                    ci.length = out->size();
                    generate_reply_headers(ci);
                }
            }
        }
        catch (const std::exception &e)
        {
            // only the tunnel of the failed client is affected
            const TunSession::Ptr session = parent()->find_session(client_pid);
            if (session)
            {
                if (parent()->destroy_session_tun(*session, os))
                    os << "Destroyed previous TAP instance due to exception\n";
            }

            const std::string error_msg = string::remove_blanks(os.str() + e.what() + '\n');
            OPENVPN_LOG_NTNL("EXCEPTION\n"
                             << error_msg);

            out = buf_from_string(error_msg);
            WS::Server::ContentInfo ci;
            ci.http_status = HTTP::Status::BadRequest;
            ci.type = "text/plain";
            ci.length = out->size();
            generate_reply_headers(ci);
        }
    }

    void http_content_in(BufferAllocated &buf) override
    {
        if (buf.defined())
            in.emplace_back(BufferAllocatedRc::Create(std::move(buf)));
    }

    BufferPtr http_content_out() override
    {
        BufferPtr ret;
        ret.swap(out);
        return ret;
    }

    bool http_out_eof() override
    {
        // OPENVPN_LOG("HTTP output EOF");
        return true;
    }

    bool http_stop(const int status, const std::string &description) override
    {
        if (status != WS::Server::Status::E_SUCCESS)
        {
            OPENVPN_LOG("INSTANCE STOP : " << WS::Server::Status::error_str(status) << " : " << description);
            return false;
        }
        else
            return true;
    }

    HANDLE get_client_pipe() const
    {
        AsioPolySock::NamedPipe *np = dynamic_cast<AsioPolySock::NamedPipe *>(sock.get());
        if (!np)
            throw Exception("only named pipe clients are allowed");
        return np->handle.native_handle();
    }

    /**
     * @brief Get the named pipe client process id
     *
     * @param client_pipe   The handle to the named pipe
     * @return DWORD        The client process id
     */
    DWORD get_client_pid(const HANDLE client_pipe)
    {
        return NamedPipePeerInfo::get_pid(client_pipe, true);
    }

    std::wstring get_client_exe(const HANDLE client_pipe)
    {
        Win::NamedPipePeerInfoClient npinfo(client_pipe);
        return npinfo.exe_path;
    }

    Win::ScopedHANDLE get_client_process(const HANDLE pipe, ULONG pid_hint) const
    {
        pid_hint = Win::NamedPipePeerInfo::get_pid(pipe, true);
        if (!pid_hint)
            throw Exception("cannot determine client PID");
        return Win::NamedPipePeerInfo::get_process(pid_hint, false);
    }

    MyListener *parent()
    {
        return static_cast<MyListener *>(get_parent());
    }

    BufferList in;
    BufferPtr out;
};

class MyClientFactory : public WS::Server::Listener::Client::Factory
{
  public:
    typedef RCPtr<MyClientFactory> Ptr;

    WS::Server::Listener::Client::Ptr new_client(WS::Server::Listener::Client::Initializer &ci) override
    {
        return new MyClientInstance(ci);
    }
};

class MyService : public Win::Service
{
  public:
    MyService()
        : Win::Service(config())
    {
    }

    void service_work(DWORD argc, LPWSTR *argv) override
    {
        if (is_service())
        {
            try
            {
                log.reset(new Win::LogFile(log_fn(), "", false));
            }
            catch (const std::exception &e)
            {
                std::cerr << e.what() << "\n";
            }
        }
        if (!log)
            log.reset(new LogBaseSimple());

        io_context.reset(new openvpn_io::io_context(1)); // concurrency hint=1

        log_version();

        MyConfig conf;

        // Refuse to share the pipe with another agent, e.g. "ovpnagent run"
        // while the service is running. Windows reports the process that
        // created the pipe first as its server, so clients would validate
        // against that one and fail once it is gone.
        if (::WaitNamedPipeA(conf.pipe_name.c_str(), 0) || ::GetLastError() != ERROR_FILE_NOT_FOUND)
            throw Exception("another agent is already serving " + conf.pipe_name);

        Win::NamedPipePeerInfo::allow_client_query();
        TunWin::NRPT::delete_rules(0); // remove stale NRPT rules

        WS::Server::Config::Ptr hconf = new WS::Server::Config();
        hconf->http_server_id = OVPNAGENT_NAME_STRING "/" HTTP_SERVER_VERSION;
        hconf->frame = frame_init_simple(2048);
        hconf->stats.reset(new MySessionStats);

        // DACL string for creating named pipe
        hconf->sddl_string = "D:"                           // discretionary ACL
                             "(D;OICI;GA;;;S-1-5-2)"        // deny all access for network users
                             "(A;OICI;GA;;;S-1-5-32-544)"   // allow full access to Admin group
                             "(A;OICI;GA;;;S-1-5-18)"       // allow full access to Local System account
                             "(D;OICI;0x4;;;S-1-1-0)"       // deny FILE_CREATE_PIPE_INSTANCE for Everyone
                             "(A;OICI;GRGW;;;S-1-5-11)"     // allow read/write access for authenticated users
                             "(A;OICI;GRGW;;;S-1-5-32-546)" // allow read/write access for built-in guest account
            ;

        Listen::List ll;
        const unsigned int n_pipe_instances = 4;
        for (unsigned int i = 0; i < n_pipe_instances; ++i)
        {
            Listen::Item li;
            li.directive = "http-listen";
            li.addr = conf.pipe_name;
            li.proto = Protocol(Protocol::NamedPipe);
            li.ssl = Listen::Item::SSLOff;
            li.n_threads = n_pipe_instances;
            ll.push_back(std::move(li));
        }

        MyClientFactory::Ptr factory = new MyClientFactory();
        listener.reset(new MyListener(conf, *io_context, hconf, ll, factory));
        listener->start();

        report_service_running();

        io_context->run();
    }

    // Called by service control manager in another thread
    // to signal the service_work() method to exit.
    void service_stop() override
    {
        openvpn_io::post(*io_context, [this]()
                         {
	if (listener)
	  {
	    listener->close_all_sessions("exit");
	    listener->stop();
	  } });
    }

  private:
    static Config config()
    {
        Config c;
        c.name = OVPNAGENT_NAME_STRING;
        c.display_name = "OpenVPN Agent " OVPNAGENT_NAME_STRING;
        c.autostart = true;
        c.restart_on_fail = true;
        return c;
    }

    static std::string log_fn()
    {
        const std::string modname = Win::module_name_utf8();
        const std::string moddir = path::dirname(modname);
        const std::string fn = path::join(moddir, "agent.log");
        return fn;
    }

    std::unique_ptr<openvpn_io::io_context> io_context;
    MyListener::Ptr listener;
    LogBase::Ptr log;
};

OPENVPN_SIMPLE_EXCEPTION(usage);

int main(int argc, char *argv[])
{
    int ret = 0;

    // process-wide initialization
    InitProcess::Init init;

    try
    {
        MyService serv;
        if (argc >= 2)
        {
            const std::string arg = argv[1];
            if (arg == "run")
                serv.service_work(0, nullptr);
            else if (arg == "install")
                serv.install();
            else if (arg == "remove")
                serv.remove();
            else if (arg == "modname")
                std::wcout << Win::module_name() << "\n";
            else if (arg == "help")
            {
                std::cout << "usage: ovpnagent [options]\n";
                std::cout << "  run       -- run in foreground (for debugging)\n";
                std::cout << "  install   -- install as service\n";
                std::cout << "  remove    -- uninstall\n";
                std::cout << "  modname   -- show module name\n";
                std::cout << "  help      -- show help message\n";
                std::cout << "  [default] -- start as service\n";
            }
            else
            {
                std::cout << "unrecognized option, use 'help' for more info\n";
                ret = 2;
            }
        }
        else
            serv.start();
    }
    catch (const std::exception &e)
    {
        std::cout << "ovpnagent: " << e.what() << "\n";
        ret = 1;
    }

    return ret;
}
