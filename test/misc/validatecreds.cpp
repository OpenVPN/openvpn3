// Test Unicode::is_valid_utf8(), validate_auth_cred(),
// and AuthCreds::is_valid().  Throws exception on failure.

#include <iostream>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/auth/validatecreds.hpp>
#include <openvpn/auth/authcreds.hpp>

using namespace openvpn;

void validate(const std::string& cred, const bool expected_result)
{
  OPENVPN_LOG("VALIDATE '" << cred << "' expected res=" << expected_result);
  const bool actual_result = validate_auth_cred(cred);
  if (actual_result != expected_result)
    OPENVPN_THROW_EXCEPTION("ERROR: expected result=" << expected_result << " but actual result=" << actual_result);
}

void test1()
{
  validate("foobar", true);
  validate("foo bar", false);
  validate("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true);
  validate("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", false);
  validate("hello\x07there", false);
  validate("Привет", true);
  validate("\xFF\xFF\xFF\xFF", false);
}

void validate_creds(std::string username, std::string password, const bool expected_result)
{
  OPENVPN_LOG("VALIDATE username='" << username << "' password='" << password << "' expected res=" << expected_result);
  SafeString password_safe(password);
  const AuthCreds ac(std::move(username), std::move(password_safe), "");
  const bool actual_result = ac.is_valid();
  if (actual_result != expected_result)
    OPENVPN_THROW_EXCEPTION("ERROR: expected result=" << expected_result << " but actual result=" << actual_result);
}

void test2()
{
  validate_creds("foo", "bar", true);
  validate_creds("", "bar", false);
  validate_creds("foo", "", true);
  validate_creds("Привет", "trouble", true);
  validate_creds("Привет", "", true);
  validate_creds("foo bar", "zoo", false);
  validate_creds("hello\x07there", "pass", false);
  validate_creds("হ্যালো", "హలో", true);
  validate_creds("yyy", "\xFF\xFF\xFF\xFF", false);
}

void validate_utf8(const std::string& str, const size_t max_len_flags, const bool expected_result)
{
  OPENVPN_LOG("VALIDATE UTF8 '" << str << "' expected res=" << expected_result);
  const bool actual_result = Unicode::is_valid_utf8(str, max_len_flags);
  if (actual_result != expected_result)
    OPENVPN_THROW_EXCEPTION("ERROR: expected result=" << expected_result << " but actual result=" << actual_result);
}

void test3()
{
  validate_utf8("", 0, true);
  validate_utf8("test", 0, true);
  validate_utf8("Привет", 0, true);
  validate_utf8("Привет", 6, true);
  validate_utf8("Привет", 5, false);
  validate_utf8("hello\x07there", 0, true);
  validate_utf8("hello\x07there", Unicode::UTF8_NO_CTRL, false);
  validate_utf8("\xFF\xFF\xFF\xFF", 0, false);
  validate_utf8("hello there", 0, true);
  validate_utf8("hello there", Unicode::UTF8_NO_SPACE, false);
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    test1();
    test2();
    test3();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
