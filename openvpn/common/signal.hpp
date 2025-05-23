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

#ifndef OPENVPN_COMMON_SIGNAL_H
#define OPENVPN_COMMON_SIGNAL_H

#include <openvpn/common/platform.hpp>

#if !defined(OPENVPN_PLATFORM_WIN)

#include <signal.h>

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

namespace openvpn {
class Signal
{
  public:
    OPENVPN_SIMPLE_EXCEPTION(signal_error);

    typedef void (*handler_t)(int signum);

    enum
    {
        F_SIGINT = (1 << 0),
        F_SIGTERM = (1 << 1),
        F_SIGHUP = (1 << 2),
        F_SIGUSR1 = (1 << 3),
        F_SIGUSR2 = (1 << 4),
        F_SIGPIPE = (1 << 5),
    };

    /**
     * configure a signal handler to be active on the signal specified in the
     * \c flags parameter. The signal handler will receive the original system
     * signal numbers and not the ones from the enum of this class.
     * @param handler
     * @param flags
     */
    Signal(const handler_t handler, const unsigned int flags)
    {
        struct sigaction sa;
        sa.sa_handler = handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART; // restart functions if interrupted by handler
        sigconf(sa, flags_ = flags);
    }

    ~Signal() noexcept(false)
    {
        reset_to_defaults(flags_);
    }

    static void reset_all_to_defaults()
    {
        reset_to_defaults(F_SIGINT | F_SIGTERM | F_SIGHUP | F_SIGUSR1 | F_SIGUSR2 | F_SIGPIPE);
    }

    static void reset_to_defaults(const unsigned int flags)
    {
        struct sigaction sa;
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigconf(sa, flags);
    }

  private:
    static void sigconf(struct sigaction &sa, const unsigned int flags)
    {
        if (flags & F_SIGINT)
            sigact(sa, SIGINT);
        if (flags & F_SIGTERM)
            sigact(sa, SIGTERM);
        if (flags & F_SIGHUP)
            sigact(sa, SIGHUP);
        if (flags & F_SIGUSR1)
            sigact(sa, SIGUSR1);
        if (flags & F_SIGUSR2)
            sigact(sa, SIGUSR2);
        if (flags & F_SIGPIPE)
            sigact(sa, SIGPIPE);
    }

    static void sigact(struct sigaction &sa, const int sig)
    {
        if (sigaction(sig, &sa, nullptr) == -1)
            throw signal_error();
    }

    unsigned int flags_;
};

// Like Asio posix_signal_blocker, but only block certain signals
class SignalBlocker
{
    SignalBlocker(const SignalBlocker &) = delete;
    SignalBlocker &operator=(const SignalBlocker &) = delete;

  public:
    SignalBlocker(const unsigned int flags) // use signal mask from class Signal
        : blocked_(false)
    {
        sigset_t new_mask;
        sigemptyset(&new_mask);
        if (flags & Signal::F_SIGINT)
            sigaddset(&new_mask, SIGINT);
        if (flags & Signal::F_SIGTERM)
            sigaddset(&new_mask, SIGTERM);
        if (flags & Signal::F_SIGHUP)
            sigaddset(&new_mask, SIGHUP);
        if (flags & Signal::F_SIGUSR1)
            sigaddset(&new_mask, SIGUSR1);
        if (flags & Signal::F_SIGUSR2)
            sigaddset(&new_mask, SIGUSR2);
        if (flags & Signal::F_SIGPIPE)
            sigaddset(&new_mask, SIGPIPE);
        blocked_ = (pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask_) == 0);
    }

    const sigset_t *orig_sigset() const
    {
        if (blocked_)
            return &old_mask_;
        else
            return nullptr;
    }

    // Destructor restores the previous signal mask.
    ~SignalBlocker()
    {
        if (blocked_)
            pthread_sigmask(SIG_SETMASK, &old_mask_, 0);
    }

  private:
    // Have signals been blocked.
    bool blocked_;

    // The previous signal mask.
    sigset_t old_mask_;
};

// Like SignalBlocker, but block specific signals in default constructor
struct SignalBlockerDefault : public SignalBlocker
{
    SignalBlockerDefault()
        : SignalBlocker( // these signals should be handled by parent thread
              Signal::F_SIGINT
              | Signal::F_SIGTERM
              | Signal::F_SIGHUP
              | Signal::F_SIGUSR1
              | Signal::F_SIGUSR2
              | Signal::F_SIGPIPE)
    {
    }
};

struct SignalBlockerPipe : public SignalBlocker
{
    SignalBlockerPipe()
        : SignalBlocker(Signal::F_SIGPIPE)
    {
    }
};

} // namespace openvpn
#endif
#endif
