#ifndef OPENVPN_BUFFER_MEMQ_H
#define OPENVPN_BUFFER_MEMQ_H

#include <queue>

#include <openvpn/buffer/buffer.hpp>

namespace openvpn {

class MemQ {
public:
  bool empty() const { return q.empty(); }

  size_t pending() const {
    return empty() ? 0 : q.front()->size();
  }

  void clear() {
    while (!q.empty())
      q.pop();
  }

  void write(BufferPtr& bp) {
    q.push(bp);
  }
  void write(const void *data, size_t size) {
    q.push(BufferPtr(new buffer(data, size)));
  }

  BufferPtr read() {
    BufferPtr ret = q.front();
    q.pop();
    return ret;
  }
  size_t read(void *data, size_t len)
  {
    BufferPtr& b = q.front();
    const size_t ret = b->read(data, len);
    if (b->empty())
      q.pop();
    return ret;
  }

private:
  std::queue<BufferPtr> q;
};

} // namespace openvpn

#endif // OPENVPN_BUFFER_MEMQ_H
