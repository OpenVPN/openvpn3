#include "test_common.hpp"

#include <iostream>

#include <openvpn/common/path.hpp>

using namespace openvpn;

// Ugly hack
static std::stringstream out;

void test_basename(const std::string &path)
{
    const std::string res = path::basename(path);
    out << "basename('" << path << "') = '" << res << "'\n";
}

void dirname(const std::string &path)
{
    const std::string res = path::dirname(path);
    out << "dirname('" << path << "') = '" << res << "'\n";
}

void ext(const std::string &path)
{
    const std::string res = path::ext(path);
    out << "ext('" << path << "') = '" << res << "'\n";
}

void is_flat(const std::string &path)
{
    const bool res = path::is_flat(path);
    out << "is_flat('" << path << "') = " << res << '\n';
}

void join(const std::string &p1, const std::string &p2)
{
    const std::string res = path::join(p1, p2);
    out << "join('" << p1 << "', '" << p2 << "') = '" << res << "'\n";
}

void join3(const std::string &p1, const std::string &p2, const std::string &p3)
{
    const std::string res = path::join(p1, p2, p3);
    out << "join('" << p1 << "', '" << p2 << "', '" << p3 << "') = '" << res << "'\n";
}

void join4(const std::string &p1, const std::string &p2, const std::string &p3, const std::string &p4)
{
    const std::string res = path::join(p1, p2, p3, p4);
    out << "join('" << p1 << "', '" << p2 << "', '" << p3 << "', '" << p4 << "') = '" << res << "'\n";
}

void splitjoin(const std::string &p1)
{
    const std::string d = path::dirname(p1);
    const std::string b = path::basename(p1);
    const std::string p2 = path::join(d, b);
    out << "splitjoin p1='" << p1 << "' dir='" << d << "' bn='" << b << "' p2='" << p2 << "'\n";
}

TEST(Path, Test1)
{
    out.clear();
    out.str("");
    // basename
    test_basename("");
    test_basename("/");
    test_basename("/foo");
    test_basename("/foo/bar");
    test_basename("foo/bar/boo");
    test_basename("foo/bar/");
    test_basename("foo\\bar\\boo");

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

    // join (3 or more parms)
    join3("", "", "three");
    join3("one", "two", "three");
    join3("one", "/two", "three");
    join4("one", "two", "three", "four");
    join4("one", "two", "", "four");

    // ext
    ext("");
    ext("foo");
    ext("foo.bar");
    ext("foo.bar.moo");
    ext("foo.");
    ext(".foo");

    // splitjoin
    splitjoin("");
    splitjoin("/");
    splitjoin("/foo");
    splitjoin("/foo/");
    splitjoin("/foo/bar");
    splitjoin("/foo/bar/");

#ifdef WIN32
    ASSERT_EQ(getExpectedOutput("test_path_win32.txt"), out.str());
#else
    ASSERT_EQ(getExpectedOutput("test_path.txt"), out.str());
#endif
}

void test_contained(const std::string &path, const bool expected)
{
    const bool contained = path::is_contained(path);
    ASSERT_EQ(contained, expected);
}

TEST(Path, Test2)
{
    test_contained("", false);
    test_contained(".", true);
    test_contained("..", false);
    test_contained("..x", true);
    test_contained("x..", true);
    test_contained("...", true);
    test_contained("../", false);
    test_contained("/..", false);
    test_contained("/foo", false);
    test_contained("foo", true);
    test_contained("foo/bar", true);
    test_contained("foo//bar", true);
    test_contained("foo/bar/", true);
    test_contained("foo/bar//", true);
    test_contained("..foo", true);
    test_contained(".foo", true);
    test_contained("./foo", true);
    test_contained("../foo", false);
    test_contained("..//foo", false);
    test_contained(".../foo", true);
    test_contained("foo/..", false);
    test_contained("foo/.", true);
    test_contained("foo//..", false);
    test_contained("foo/...", true);
    test_contained("foo/./bar", true);
    test_contained("foo/../bar", false);
    test_contained("foo/.../bar", true);
}
