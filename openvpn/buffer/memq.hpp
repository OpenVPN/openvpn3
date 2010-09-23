#ifndef OPENVPN_BUFFER_MEMQ_H
#define OPENVPN_BUFFER_MEMQ_H

#include <iostream>
#include <queue>

#include <boost/intrusive_ptr.hpp>
#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

class MemQ {
public:
  typedef BufferRC buffer;
  typedef boost::intrusive_ptr<buffer> buffer_ptr;

  bool empty() const { return q.empty(); }

  size_t pending() const {
    return empty() ? 0 : q.front()->size();
  }

  void clear() {
    while (!q.empty())
      q.pop();
  }

  void write(buffer_ptr& bp) {
    q.push(bp);
  }
  void write(const void *data, size_t size) {
    q.push(buffer_ptr(new buffer(data, size)));
  }

  buffer_ptr read() {
    buffer_ptr ret = q.front();
    q.pop();
    return ret;
  }
  size_t read(void *data, size_t len)
  {
    buffer_ptr& b = q.front();
    const size_t ret = b->read(data, len);
    if (b->empty())
      q.pop();
    return ret;
  }

private:
  std::queue<buffer_ptr> q;
};

} // namespace openvpn

#endif // OPENVPN_BUFFER_MEMQ_H
