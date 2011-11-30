#ifndef OPENVPN_COMMON_USECOUNT_H
#define OPENVPN_COMMON_USECOUNT_H

namespace openvpn {

  class UseCount
  {
  public:
    UseCount(int& count)
      : count_(count)
    {
      ++count_;
    }

    ~UseCount()
    {
      --count_;
    }

  private:
    int& count_;
  };

} // namespace openvpn

#endif // OPENVPN_COMMON_USECOUNT_H
