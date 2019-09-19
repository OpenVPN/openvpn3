// TEST : {"cmd": "./go sess_id"}

#include <iostream>
#include <unordered_map>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/random/devurand.hpp>
#include <openvpn/common/sess_id.hpp>
#include <openvpn/openssl/util/tokenencrypt.hpp>

using namespace openvpn;

void test()
{
  DevURand rng;

  // test 1
  {
    std::cout << "=== TEST 1 ===" << std::endl;
    const SessionID64 sid1(rng);
    std::cout << "SID1: " << sid1 << std::endl;

    const SessionID64 sid2(sid1.to_string());
    if (!sid1.defined() || !sid2.defined())
      throw Exception("FAIL sid1 or sid2 is undefined");
    if (sid1 != sid2)
      throw Exception("FAIL sid1 != sid2: " + sid2.to_string());

    const SessionID128 sid3(rng);
    std::cout << "SID3: " << sid3 << std::endl;
    if (sid1.eq_weak(sid3))
      throw Exception("FAIL sid1 ~== sid3");
    if (sid3.eq_weak(sid1))
      throw Exception("FAIL sid3 ~== sid1");

    for (int i = 1; i <= 4; ++i)
      {
	std::cout << "---- " << i << " ----" << std::endl;
	const TokenEncrypt::Key key(rng);
	TokenEncryptDecrypt ted(key);
	const SessionID128 sid3_enc(sid3, ted.encrypt);
	std::cout << "SID3 (enc): " << sid3_enc << std::endl;
	const SessionID128 sid3_dec(sid3_enc, ted.decrypt);
	std::cout << "SID3 (dec): " << sid3_dec << std::endl;
      }
  }

  // test 2
  {
    std::cout << "=== TEST 2 ===" << std::endl;
    const SessionID64 sid1(rng);
    std::cout << "SID1: " << sid1 << std::endl;
    const SessionID128 sid2(rng);
    std::cout << "SID2: " << sid2 << std::endl;

    const SessionID128 sid1_exp(sid1);
    std::cout << "SID1_EXP: " << sid1_exp << std::endl;
    const SessionID64 sid2_trunc(sid2);
    std::cout << "SID2_TRUNC: " << sid2_trunc << std::endl;
  }

  // test 3
  {
    std::cout << "=== TEST 3 ===" << std::endl;
    const SessionID64 ns;
    if (ns.defined())
      throw Exception("FAIL default constructed SessionID is defined");
  }

  // test 4
  {
    std::cout << "=== TEST 4 ===" << std::endl;
    const SessionID128 x;
    const SessionID128 a("YmtN7B2edrDRlefk3vQ_YQ..");
    const SessionID128 b("YmtN7B2edrDRlefk3vQ_YA..");
    const SessionID64  c("YmtN7B2edrA.");
    const SessionID128 d(c);
    std::cout << "a: " << a << std::endl;
    std::cout << "b: " << b << std::endl;
    std::cout << "c: " << c << std::endl;
    std::cout << "d: " << d << std::endl;
    if (a == b)
      throw Exception("test4: wrong, not equal");
    if (!a.eq_weak(b))
      throw Exception("test4/1: wrong, weakly equal");
    if (!a.eq_weak(c))
      throw Exception("test4/2: wrong, weakly equal");
    if (!b.eq_weak(c))
      throw Exception("test4/3: wrong, weakly equal");

    std::unordered_map<SessionID128, std::string> map;
    const std::unordered_map<SessionID128, std::string>& cmap = map;
    map[a] = "hello";
    if (!b.find_weak(map, true))
      throw Exception("test4/1: wrong, weak exists");
    if (!d.find_weak(map, true))
      throw Exception("test4/2: wrong, weak exists");
    if (a.find_weak(map, true))
      throw Exception("test4/3: wrong, weak doesn't exist");
    if (!a.find_weak(map, false))
      throw Exception("test4/4: wrong, weak exists");
    if (x.find_weak(map, true))
      throw Exception("test4: wrong, weak doesn't exist");
    const SessionID128* s1 = d.find_weak(cmap, true);
    if (!s1)
      throw Exception("test4: can't find s1");
    std::cout << "lookup: " << *s1 << ' ' << std::endl;
    const SessionID128* s2 = x.find_weak(cmap, true);
    if (s2)
      throw Exception("test4: shouldn't have found s2");
  }

#if 1 // performance
  {
    std::cout << "=== TEST PERF ===" << std::endl;
    const SessionID128 sid(rng);
    const TokenEncrypt::Key key(rng);
    TokenEncryptDecrypt ted(key);
    for (size_t i = 0; i < 1000; ++i)
      {
	const SessionID128 sid_enc(sid, ted.encrypt);
	const SessionID128 sid_dec(sid_enc, ted.decrypt);
	if (sid != sid_dec)
	  throw Exception("FAIL!");
      }
  }
#endif
}

int main(int /*argc*/, char* /*argv*/[])
{
  base64_init_static();
  try {
    test();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  base64_uninit_static();
  return 0;
}
