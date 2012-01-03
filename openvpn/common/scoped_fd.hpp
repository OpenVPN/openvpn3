#ifndef OPENVPN_COMMON_SCOPED_FD_H
#define OPENVPN_COMMON_SCOPED_FD_H

#include <unistd.h> // for close()

#include <boost/noncopyable.hpp>

namespace openvpn {

  // like boost::scoped_ptr but has release method
  class ScopedFD : boost::noncopyable
  {
  public:
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

    ~ScopedFD()
    {
      if (defined())
	close(fd);
    }

  private:
    int fd;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_SCOPED_FD_H
