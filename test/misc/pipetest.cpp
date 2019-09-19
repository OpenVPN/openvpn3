// TEST : {"cmd": "./go pipetest"}

#include <iostream>
#include <utility>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/common/string.hpp>
#include <openvpn/common/process.hpp>

using namespace openvpn;

void test()
{
  RedirectPipe::InOut io;

  {
    Argv argv;
    io.in = "one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten\n";
    argv.emplace_back("sort");
    argv.emplace_back("-u");
    OPENVPN_LOG(argv.to_string());
    const int status = system_cmd("/usr/bin/sort", argv, nullptr, io, 0);

    if (status)
      OPENVPN_THROW_EXCEPTION("bad sort status=" << status << " stderr=" << io.err);

    const std::string expected = "eight\nfive\nfour\nnine\none\nseven\nsix\nten\nthree\ntwo\n";
    if (io.out != expected)
      OPENVPN_THROW_EXCEPTION("bad sort EXPECTED:\n" << expected << "ACTUAL:\n" << io.out);
  }
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    test();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
