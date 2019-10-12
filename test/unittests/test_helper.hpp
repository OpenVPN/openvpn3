//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2019 OpenVPN Inc.
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

#pragma once

#include <openvpn/log/logbase.hpp>
#include <iostream>
#include <gtest/gtest.h>

namespace openvpn {
  class LogOutputCollector : public LogBase
  {
  public:
    LogOutputCollector() : log_context(this)
    {
    }

    void log(const std::string& l) override
    {
      std::lock_guard<std::mutex> lock(mutex);

      if (output_log)
	std::cout << l;
      if (collect_log)
	out << l;
    }

    /**
     * Return the collected log out
     * @return the log output as string
     */
    std::string getOutput() const
    {
      return out.str();
    }

    /**
     * Allow to access the underlying output stream to direct
     * output from function that want to write to a stream to it
     * @return that will be captured by this log
     */
    std::ostream& getStream()
    {
      return out;
    }

    /**
     * Changes if the logging to stdout should be done
     * @param doOutput
     */
    void setPrintOutput(bool doOutput)
    {
      output_log = doOutput;
    }

    /**
     * Return current state of stdout output
     * @return current state of output
     */
    bool isStdoutEnabled() const
    {
      return output_log;
    }

    /**
     * Starts collecting log output. This will also
     * disable stdout output and clear the collected output if there is any
     */
    void startCollecting()
    {
      collect_log = true;
      output_log = false;
      // Reset our buffer
      out.str(std::string());
      out.clear();
    }

    /**
     * Stops collecting log output. Will reenable stdout output.
     * @return the output collected
     */
    std::string stopCollecting()
    {
      collect_log = false;
      output_log = true;
      return getOutput();
    }

  private:
    bool output_log = true;
    bool collect_log = false;
    std::stringstream out;
    std::mutex mutex{};
    Log::Context log_context;
  };
}

extern openvpn::LogOutputCollector* testLog;

/**
 * Overrides stdout during the run of a function. Primarly for silencing
 * log function that throw an exception when something is wrong
 * @param doLogOutput Use stdout while running
 * @param test_func function to run
 */
inline void override_logOutput(bool doLogOutput, void (* test_func)())
{
  bool previousOutputState = testLog->isStdoutEnabled();
  testLog->setPrintOutput(doLogOutput);
  test_func();
  testLog->setPrintOutput(previousOutputState);
}