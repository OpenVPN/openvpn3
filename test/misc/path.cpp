#include <iostream>

//#define OPENVPN_PATH_SIMULATE_WINDOWS

#include <openvpn/common/size.hpp>
#include <openvpn/common/exception.hpp>
#include <openvpn/common/path.hpp>

using namespace openvpn;

void basename(const std::string& path)
{
  const std::string res = path::basename(path);
  std::cout << "basename('" << path << "') = '" << res << "'" << std::endl;
}

void dirname(const std::string& path)
{
  const std::string res = path::dirname(path);
  std::cout << "dirname('" << path << "') = '" << res << "'" << std::endl;
}

void ext(const std::string& path)
{
  const std::string res = path::ext(path);
  std::cout << "ext('" << path << "') = '" << res << "'" << std::endl;
}

void is_flat(const std::string& path)
{
  const bool res = path::is_flat(path);
  std::cout << "is_flat('" << path << "') = " << res << std::endl;
}

void join(const std::string& p1, const std::string& p2)
{
  const std::string res = path::join(p1, p2);
  std::cout << "join('" << p1 << "', '" << p2 << "') = '" << res << "'" << std::endl;
}


int main()
{
  try {
    // basename
    basename("");
    basename("/");
    basename("/foo");
    basename("/foo/bar");
    basename("foo/bar/boo");
    basename("foo/bar/");
    basename("foo\\bar\\boo");

    // dirname
    dirname("");
    dirname("/");
    dirname("/foo");
    dirname("/foo/bar");
    dirname("foo/bar/boo");
    dirname("foo/bar/");
    dirname("foo\\bar\\boo");

    // is_flat
    is_flat("");
    is_flat("/");
    is_flat("foo.bar");
    is_flat("foo/bar");
    is_flat("c:/foo");
    is_flat("c:foo");
    is_flat("z:\\foo");
    is_flat(".");
    is_flat("..");
    is_flat("./foo");

    // join
    join("foo", "bar");
    join("foo", "");
    join("", "foo/bar");
    join("", "bar");
    join("foo", "/bar");
    join("/", "bar");

    // ext
    ext("");
    ext("foo");
    ext("foo.bar");
    ext("foo.bar.moo");
    ext("foo.");
    ext(".foo");
  }
  catch (const std::exception& e)
    {
      std::cerr << "Exception: " << e.what() << std::endl;
      return 1;
    }
  return 0;
}
