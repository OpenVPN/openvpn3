#include <iostream>

#include <openvpn/crypto/static_key.hpp>

const char key_text[] =
  "-----BEGIN OpenVPN Static key V1-----\n"
  "bd28e7947597929093371be4cf55fd78\n"
  "98a70d0feffd389f70ea606635ed0371\n"
  "57045695a770264ca0b2c251cb5c65fe\n"
  "447d9b28855cf199bc3d9527e5f88a59\n"
  "5cd213b5a71b47f11a915a77e3a7aed7\n"
  "fa901d864150b64eb8d424383e5564dd\n"
  "23e5b5fa8d16dfe2d37b946e8f22bb58\n"
  "a5b904062bdcea35007c6825250a1c00\n"
  "a2a54bd892fa20edbcfe4fe1fa8a786c\n"
  "5c1102a3b53e294c729b37a24842f9c9\n"
  "b72018b990aff058bbeeaf18f586cd5c\n"
  "d70475328caed6d9662937a3c970f253\n"
  "8495988c6c72c0ef8da720c342ac6405\n"
  "a61da0fd18ddfd106aeee1736772baad\n"
  "014703f549480c61080aa963f8b10a4a\n"
  "f7591ead4710bd0e74c0b37e37c84374\n"
  "-----END OpenVPN Static key V1-----\n";

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    openvpn::OpenVPNStaticKey sk;
    sk.parse(std::string(key_text));
    std::string rend = sk.render();
    std::cout << rend;
  }
  catch (std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
