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

    char *const *c_argv() const
    {
      return cargv;
    }

    char **c_argv()
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

  inline pid_t system_cmd_async(const std::string& cmd,
				const Argv& argv,
				const Environ* env,
				RedirectBase* redir)
  {
    ArgvWrapper argv_wrap(argv);
    std::unique_ptr<ArgvWrapper> env_wrap;
    if (env)
      env_wrap.reset(new ArgvWrapper(*env));
    const pid_t pid = ::fork();
    if (pid == pid_t(0)) /* child side */
      {
	if (redir)
	  redir->redirect();
	::execve(cmd.c_str(),
		 argv_wrap.c_argv(),
		 env_wrap ? env_wrap->c_argv() : ::environ);
	::exit(127);
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

  inline int system_cmd(const std::string& cmd,
			const Argv& argv,
			RedirectBase* redir,
			const Environ* env)
  {
    const pid_t pid = system_cmd_async(cmd, argv, env, redir);
    if (pid < pid_t(0))
      return -1;
    int status = -1;
    if (::waitpid(pid, &status, 0) == pid)
      {
	if (WIFEXITED(status))
	  return WEXITSTATUS(status);
      }
    return -1;
  }

  inline int system_cmd(const std::string& cmd, const Argv& argv)
  {
    return system_cmd(cmd, argv, nullptr, nullptr);
  }

  inline int system_cmd(const Argv& argv)
  {
    int ret = -1;
    if (argv.size())
      ret = system_cmd(argv[0], argv);
    return ret;
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

    virtual void execute()
    {
      if (!argv.empty())
	{
	  OPENVPN_LOG(to_string());
	  system_cmd(argv[0], argv);
	}
      else
	OPENVPN_LOG("WARNING: Command::execute called with empty argv");
    }

    virtual std::string to_string() const
    {
      return argv.to_string();
    }

    Argv argv;
  };

}

#endif // OPENVPN_COMMON_PROCESS_H
