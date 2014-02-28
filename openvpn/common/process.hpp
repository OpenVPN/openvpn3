//
//  process.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

// General-purpose classes for instantiating a posix process with arguments.

#ifndef OPENVPN_COMMON_PROCESS_H
#define OPENVPN_COMMON_PROCESS_H

#include <cstring>     // memcpy
#include <stdlib.h>    // exit
#include <unistd.h>    // fork, execve
#include <sys/types.h> // waitpid
#include <sys/wait.h>  // waitpid

#include <string>

#include <boost/noncopyable.hpp>

#include <openvpn/common/types.hpp>
#include <openvpn/common/action.hpp>

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
      for (const_iterator i = begin(); i != end(); ++i)
	{
	  if (!first)
	    ret += ' ';
	  ret += *i;
	  first = false;
	}
      return ret;
    }
  };

  class ArgvWrapper : boost::noncopyable
  {
  public:
    ArgvWrapper(const Argv& argv)
    {
      size_t i;
      argc = argv.size();
      cargv = new char *[argc+1];
      for (i = 0; i < argc; ++i)
	cargv[i] = string_alloc(argv[i]);
      cargv[i] = NULL;
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

  inline int system_cmd(const std::string& cmd, const Argv& argv)
  {
    int ret = -1;
    ArgvWrapper argv_wrap(argv);
    const pid_t pid = fork();
    if (pid == pid_t(0)) /* child side */
      {
	execve(cmd.c_str(), argv_wrap.c_argv(), environ);
	exit(127);
      }
    else if (pid < pid_t(0)) /* fork failed */
      ;
    else /* parent side */
      {
	if (waitpid(pid, &ret, 0) != pid)
	  ret = -1;
      }
    return ret;
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
    typedef boost::intrusive_ptr<Command> Ptr;

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
