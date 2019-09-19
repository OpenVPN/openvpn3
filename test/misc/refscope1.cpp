// TEST : {"cmd": "./go refscope1", "expected_output": "refscope1-PLATFORM.txt"}

#include <string>
#include <iostream>
#include <utility>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/random/mtrandapi.hpp>
#include <openvpn/common/sess_id.hpp>
#include <openvpn/openssl/util/tokenencrypt.hpp>

using namespace openvpn;

struct SessionID : public SessionID128
{
  SessionID()
  {
    dump("default");
  }

  SessionID(RandomAPI& rng)
    : SessionID128(rng, true)
  {
    dump("rng");
  }

  ~SessionID()
  {
    dump("destruct");
  }

  void dump(const char *prefix) const
  {
    std::cout << prefix << " : " << to_string() << std::endl;
  }
};

class Session
{
public:
  Session(RandomAPI& rng)
    : sid(rng)
  {
  }

  const SessionID& get_token() const
  {
    return sid;
  }

private:
  SessionID sid;
};

std::string name()
{
  return std::string("myname");
}

void test(Session* session)
{
  const std::string& nam = name();
  const SessionID& sid = session ? session->get_token() : SessionID();
  std::cout << "Name: " << nam << " SessID: " << sid << std::endl;
}

void run()
{
  MTRand rng(123456789);
  Session sess(rng);
  std::cout << "--- TEST1 ---" << std::endl;
  test(&sess);
  std::cout << "--- TEST2 ---" << std::endl;
  test(nullptr);
  std::cout << "--- END ---" << std::endl;
}

int main(int /*argc*/, char* /*argv*/[])
{
  base64_init_static();
  try {
    run();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  base64_uninit_static();
  return 0;
}
