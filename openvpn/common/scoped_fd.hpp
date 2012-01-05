#ifndef OPENVPN_COMMON_SCOPED_FD_H
#define OPENVPN_COMMON_SCOPED_FD_H

#include <unistd.h> // for close()

#include <boost/noncopyable.hpp>

namespace openvpn {

  // like boost::scoped_ptr but has release method
  class ScopedFD : boost::noncopyable
  {
  public:
    ScopedFD() : fd(-1) {}

    explicit ScopedFD(const int fd_arg)
      : fd(fd_arg) {}

    int release()
    {
      const int ret = fd;
      fd = -1;
      return ret;
    }

    bool defined() const
    {
      return fd >= 0;
    }

    int operator()() const
    {
      return fd;
    }

    void reset(const int fd_arg)
    {
      close();
      fd = fd_arg;
    }

    int close()
    {
      if (defined())
	{
	  const int ret = ::close(fd);
	  fd = -1;
	  return ret;
	}
      else
	return 0;
    }

    ~ScopedFD()
    {
      close();
    }

  private:
    int fd;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SCOPED_FD_H
