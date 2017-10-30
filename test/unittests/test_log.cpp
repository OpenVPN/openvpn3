#include <client/ovpncli.cpp>
#include <gtest/gtest.h>
#include <string>
#include <sstream>

namespace unittests
{  
  TEST(LogInfoTest, TestLogInfo)
  {    
    std::string msg("logMessage");
    openvpn::ClientAPI::LogInfo logInfo(msg);
    auto text = logInfo.text;

    ASSERT_EQ(text, msg);
  }
}  // namespace

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
