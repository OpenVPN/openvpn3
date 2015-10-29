//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2015 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// General-purpose classes for instantiating a posix process with arguments.

#ifndef OPENVPN_COMMON_PROCESS_H
#define OPENVPN_COMMON_PROCESS_H

#include <cstring>     // memcpy
#include <stdlib.h>    // exit
#include <unistd.h>    // fork, execve
#include <sys/types.h> // waitpid
#include <sys/wait.h>  // waitpid

#include <string>
#include <memory>

#include <openvpn/common/size.hpp>
#include <openvpn/common/action.hpp>
#include <openvpn/common/redir.hpp>
#include <openvpn/common/signal.hpp>

extern char **environ;

namespace openvpn {

  class Argv : public std::vector<std::string>
  {
  public:
    Argv(const size_t capacity=16)
    {
      reserve(capacity);
    }

    std::string to_string() const
    {
      std::string ret;
      bool first = true;
      for (const auto &s : *this)
	{
	  if (!first)
	    ret += ' ';
	  ret += s;
	  first = false;
	}
      return ret;
    }
  };

  class Environ : public std::vector<std::string>
  {
  public:
    void load_from_environ()
    {
      reserve(64);
      for (char **e = ::environ; *e != NULL; ++e)
	emplace_back(*e);
    }

    std::string to_string() const
    {
      std::string ret;
      ret.reserve(512);
      for (const auto &s : *this)
	{
	  ret += s;
	  ret += '\n';
	}
      return ret;
    }

    int find_index(const std::string& name) const
    {
      for (int i = 0; i < size(); ++i)
	{
	  const std::string& s = (*this)[i];
	  const size_t pos = s.find_first_of('=');
	  if (pos != std::string::npos)
	    {
	      if (name == s.substr(0, pos))
		return i;
	    }
	  else
	    {
	      if (name == s)
		return i;
	    }
	}
      return -1;
    }

    std::string find(const std::string& name) const
    {
      const int i = find_index(name);
      if (i >= 0)
	return value(i);
      else
	return "";
    }

    std::string value(const size_t idx) const
    {
      const std::string& s = (*this)[idx];
      const size_t pos = s.find_first_of('=');
      if (pos != std::string::npos)
	return s.substr(pos+1);
      else
	return "";
    }
  };

  class ArgvWrapper
  {
    ArgvWrapper(const ArgvWrapper&) = delete;
    ArgvWrapper& operator=(const ArgvWrapper&) = delete;

  public:
    explicit ArgvWrapper(const std::vector<std::string>& argv)
    {
      size_t i;
      argc = argv.size();
      cargv = new char *[argc+1];
      for (i = 0; i < argc; ++i)
	cargv[i] = string_alloc(argv[i]);
      cargv[i] = nullptr;
    }

    ~ArgvWrapper()
    {
      for (size_t i = 0; i < argc; ++i)
	delete [] cargv[i];
      delete [] cargv;
    }

    char *const *c_argv() const noexcept
    {
      return cargv;
    }

    char **c_argv() noexcept
    {
      return cargv;
    }

  private:
    static char *string_alloc(const std::string& s)
    {
      const char *sdata = s.c_str();
      const size_t slen = s.length();
      char *ret = new char[slen+1];
      std::memcpy(ret, sdata, slen);
      ret[slen] = '\0';
      return ret;
    }

    size_t argc;
    char **cargv;
  };

  // low-level fork/exec (async)
  inline pid_t system_cmd_async(const std::string& cmd,
				const Argv& argv,
				const Environ* env,
				RedirectBase* redir)
  {
    ArgvWrapper argv_wrap(argv);
    std::unique_ptr<ArgvWrapper> env_wrap;
    if (env)
      env_wrap.reset(new ArgvWrapper(*env));
    auto fn = cmd.c_str();
    auto av = argv_wrap.c_argv();
    auto ev = env_wrap ? env_wrap->c_argv() : ::environ;
    const pid_t pid = redir ? ::fork() : ::vfork();
    if (pid == pid_t(0)) /* child side */
      {
	if (redir)
	  redir->redirect();
	::execve(fn, av, ev);
	::_exit(127);
      }
    else if (pid < pid_t(0)) /* fork failed */
      return -1;
    else /* parent side */
      {
	if (redir)
	  redir->close();
	return pid;
      }
  }

  // completion for system_cmd_async()
  inline int system_cmd_post(const pid_t pid)
  {
    int status = -1;
    if (::waitpid(pid, &status, 0) == pid)
      {
	if (WIFEXITED(status))
	  return WEXITSTATUS(status);
      }
    return -1;
  }

  // synchronous version of system_cmd_async
  inline int system_cmd(const std::string& cmd,
			const Argv& argv,
			RedirectBase* redir,
			const Environ* env)
  {
    const pid_t pid = system_cmd_async(cmd, argv, env, redir);
    if (pid < pid_t(0))
      return -1;
    return system_cmd_post(pid);
  }

  // simple command execution
  inline int system_cmd(const std::string& cmd, const Argv& argv)
  {
    return system_cmd(cmd, argv, nullptr, nullptr);
  }

  // simple command execution
  inline int system_cmd(const Argv& argv)
  {
    int ret = -1;
    if (argv.size())
      ret = system_cmd(argv[0], argv);
    return ret;
  }

  // command execution with std::strings as
  // input/output/error (uses pipes under the
  // hood)
  inline int system_cmd(const std::string& cmd,
			const Argv& argv,
			const Environ* env,
			RedirectPipe::InOut& inout,
			const bool combine_out_err)
  {
    SignalBlockerPipe sbpipe;
    RedirectPipe remote;
    RedirectPipe local(remote, combine_out_err, !inout.in.empty());
    const pid_t pid = system_cmd_async(cmd, argv, env, &remote);
    if (pid < pid_t(0))
      return -1;
    local.transact(inout);
    return system_cmd_post(pid);
  }

  struct Command : public Action
  {
    typedef RCPtr<Command> Ptr;

    Command* copy() const
    {
      Command* ret = new Command;
      ret->argv = argv;
      return ret;
    }

    virtual void execute(std::ostream& os) override
    {
      if (!argv.empty())
	{
	  RedirectPipe::InOut inout;
	  os << to_string() << std::endl;
	  const int status = system_cmd(argv[0], argv, nullptr, inout, true);
	  if (status < 0)
	    os << "Error: command failed to execute" << std::endl;
	  os << inout.out;
	}
      else
	os << "Error: command called with empty argv" << std::endl;
    }

    virtual std::string to_string() const override
    {
      return argv.to_string();
    }

    Argv argv;
  };

}

#endif // OPENVPN_COMMON_PROCESS_H
