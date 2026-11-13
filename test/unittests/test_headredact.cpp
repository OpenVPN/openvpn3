#include "test_common.hpp"

// #define OPENVPN_HTTP_HEADERS_NO_REDACT

#include <openvpn/http/headredact.hpp>

using namespace openvpn;

static const std::string in1 = "HEADERS: POST /pg HTTP/1.1\r\n"
                               "         Host: 3.91.106.178\r\n"
                               "         User-Agent: japicli\r\n"
                               "         Authorization: Basic cGc6cHJqN1hKQUpuRkRsZ2V5MXZLaVlVcGhL\r\n"
                               "         Content-Type: application/json\r\n"
                               "         Content-Length: 49\r\n"
                               "         Accept-Encoding: lz4\r\n"
                               "         Accept: */*\r\n"
                               "         \r\n";

static const std::string out1 = "HEADERS: POST /pg HTTP/1.1\r\n"
                                "         Host: 3.91.106.178\r\n"
                                "         User-Agent: japicli\r\n"
                                "         Authorization: Basic [REDACTED]\r\n"
                                "         Content-Type: application/json\r\n"
                                "         Content-Length: 49\r\n"
                                "         Accept-Encoding: lz4\r\n"
                                "         Accept: */*\r\n"
                                "         \r\n";

static const std::string in2 = "HEADERS: POST /pg HTTP/1.1\r\n"
                               "         Host: 3.91.106.178\r\n"
                               "         User-Agent: japicli\r\n"
                               "         authorization=basic cGc6cHJqN1hKQUpuRkRsZ2V5MXZLaVlVcGhL\r\n"
                               "         Content-Type: application/json\r\n"
                               "         Content-Length: 49\r\n"
                               "         Accept-Encoding: lz4\r\n"
                               "         Accept: */*\r\n"
                               "         \r\n";

static const std::string out2 = "HEADERS: POST /pg HTTP/1.1\r\n"
                                "         Host: 3.91.106.178\r\n"
                                "         User-Agent: japicli\r\n"
                                "         authorization=basic [REDACTED]\r\n"
                                "         Content-Type: application/json\r\n"
                                "         Content-Length: 49\r\n"
                                "         Accept-Encoding: lz4\r\n"
                                "         Accept: */*\r\n"
                                "         \r\n";

TEST(Http, Headredact1)
{
    const std::string out = HTTP::headers_redact(in1);
    ASSERT_EQ(out, out1);
}

TEST(Http, Headredact2)
{
    const std::string out = HTTP::headers_redact(in2);
    ASSERT_EQ(out, out2);
}

// Format produced by HTTP::Request::to_string() / HeaderList::to_string(),
// as logged by AppServer on debug-level >= 2 (PORTALS-3679)
TEST(Http, HeadredactHeaderList)
{
    const std::string in = "HTTP Request\n"
                           "method=POST\n"
                           "uri=/api\n"
                           "version=1/1\n"
                           "[0] Host=example.com\n"
                           "[1] Authorization=Basic dXNlcjpwYXNz\n"
                           "[2] Content-Type=application/json\n";
    const std::string out = "HTTP Request\n"
                            "method=POST\n"
                            "uri=/api\n"
                            "version=1/1\n"
                            "[0] Host=example.com\n"
                            "[1] Authorization=Basic [REDACTED]\n"
                            "[2] Content-Type=application/json\n";
    ASSERT_EQ(HTTP::headers_redact(in), out);
}

TEST(Http, HeadredactCaseAndScheme)
{
    ASSERT_EQ(HTTP::headers_redact("authorization: basic dXNlcjpwYXNz\r\n"),
              "authorization: basic [REDACTED]\r\n");
    ASSERT_EQ(HTTP::headers_redact("AUTHORIZATION:Bearer abc.def.ghi\n"),
              "AUTHORIZATION:Bearer [REDACTED]\n");
    ASSERT_EQ(HTTP::headers_redact("[4] Proxy-Authorization=Basic dXNlcjpwYXNz\n"),
              "[4] Proxy-Authorization=Basic [REDACTED]\n");
}

TEST(Http, HeadredactNoScheme)
{
    ASSERT_EQ(HTTP::headers_redact("Authorization: sekrit\r\n"),
              "Authorization: [REDACTED]\r\n");
}

TEST(Http, HeadredactMultiWordValue)
{
    ASSERT_EQ(HTTP::headers_redact("Authorization: Digest username=\"u\", realm=\"x\", nonce=\"abc\", response=\"6629fae4\"\r\n"),
              "Authorization: Digest [REDACTED]\r\n");
    ASSERT_EQ(HTTP::headers_redact("[1] Authorization=Digest realm=\"x\", nonce=\"abc\"\n"),
              "[1] Authorization=Digest [REDACTED]\n");
}

TEST(Http, HeadredactUnrelated)
{
    // "authorization" not followed by ':' or '=' must be left alone
    const std::string in = "uri=/authorization/check\n"
                           "[0] X-Authorization-Mode=strict\n";
    ASSERT_EQ(HTTP::headers_redact(in), in);
}
