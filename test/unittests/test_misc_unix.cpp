#include "test_common.h"

#include <openvpn/common/tempfile.hpp>

using namespace openvpn;

std::string content1 =
  "It was a bright cold day in April, and the clocks\n"
  "were striking thirteen. Winston Smith, his chin nuzzled\n"
  "into his breast in an effort to escape the vile wind,\n"
  "slipped quickly through the glass doors of Victory\n"
  "Mansions, though not quickly enough to prevent a\n"
  "swirl of gritty dust from entering along with him.\n";

std::string content2 = "To be or not to be, that is the question?\n";

TEST(misc, tempfile)
{
  TempFile tf(getTempDirPath("tempfile-XXXXXX"), true);

  tf.write(content1);
  tf.reset();
  const std::string s1 = tf.read();
  ASSERT_EQ(s1, content1);

  tf.truncate();
  tf.write(content2);
  tf.reset();
  const std::string s2 = tf.read();
  ASSERT_EQ (s2, content2);
}