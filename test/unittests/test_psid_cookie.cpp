#include "test_common.h"

#include <openvpn/ssl/psid_cookie_impl.hpp>

using namespace openvpn;

// TEST(psid_cookie, create) {

TEST(psid_cookie, setup)
{
    PsidCookieImpl::pre_threading_setup();

    ASSERT_TRUE(true);
}
