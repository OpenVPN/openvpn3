//
//  process.hpp
//  OpenVPN
//
//  Copyright (c) 2012 OpenVPN Technologies, Inc. All rights reserved.
//

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

extern char **environ;

namespace openvpn {

  class Argv : public std::vector<std::string>
  {
  public:
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

}

#endif // OPENVPN_COMMON_PROCESS_H
