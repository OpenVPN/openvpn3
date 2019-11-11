// TEST : {"cmd": "./go headredact"}

//#define OPENVPN_HTTP_HEADERS_NO_REDACT

#include <iostream>

#include <openvpn/log/logsimple.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>

#include <openvpn/http/headredact.hpp>

using namespace openvpn;

static const std::string in1 =
    "HEADERS: POST /pg HTTP/1.1\r\n"
    "         Host: 3.91.106.178\r\n"
    "         User-Agent: japicli\r\n"
    "         Authorization: Basic cGc6cHJqN1hKQUpuRkRsZ2V5MXZLaVlVcGhL\r\n"
    "         Content-Type: application/json\r\n"
    "         Content-Length: 49\r\n"
    "         Accept-Encoding: lz4\r\n"
    "         Accept: */*\r\n"
    "         \r\n";

static const std::string out1 =
    "HEADERS: POST /pg HTTP/1.1\r\n"
    "         Host: 3.91.106.178\r\n"
    "         User-Agent: japicli\r\n"
    "         Authorization: Basic [REDACTED]\r\n"
    "         Content-Type: application/json\r\n"
    "         Content-Length: 49\r\n"
    "         Accept-Encoding: lz4\r\n"
    "         Accept: */*\r\n"
    "         \r\n";

static const std::string in2 =
    "HEADERS: POST /pg HTTP/1.1\r\n"
    "         Host: 3.91.106.178\r\n"
    "         User-Agent: japicli\r\n"
    "         authorization=basic cGc6cHJqN1hKQUpuRkRsZ2V5MXZLaVlVcGhL\r\n"
    "         Content-Type: application/json\r\n"
    "         Content-Length: 49\r\n"
    "         Accept-Encoding: lz4\r\n"
    "         Accept: */*\r\n"
    "         \r\n";

static const std::string out2 =
    "HEADERS: POST /pg HTTP/1.1\r\n"
    "         Host: 3.91.106.178\r\n"
    "         User-Agent: japicli\r\n"
    "         authorization=basic [REDACTED]\r\n"
    "         Content-Type: application/json\r\n"
    "         Content-Length: 49\r\n"
    "         Accept-Encoding: lz4\r\n"
    "         Accept: */*\r\n"
    "         \r\n";

void test1()
{
  const std::string out = HTTP::headers_redact(in1);
  OPENVPN_LOG_STRING(out);
  if (out != out1)
    throw Exception("test1 failed");
}

void test2()
{
  const std::string out = HTTP::headers_redact(in2);
  OPENVPN_LOG_STRING(out);
  if (out != out2)
    throw Exception("test2 failed");
}

int main(int /*argc*/, char* /*argv*/[])
{
  try {
    test1();
    test2();
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
