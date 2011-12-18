#ifndef OPENVPN_TUN_LAYER_H
#define OPENVPN_TUN_LAYER_H

namespace openvpn {
  class Layer
  {
  public:
    enum Type {
      NONE,
      OSI_LAYER_2,
      OSI_LAYER_3,
    };

    Layer() : type_(NONE) {}
    explicit Layer(const Type t) : type_(t) {}
    Type operator()() const { return type_; }

    const char *dev_type() const
    {
      switch (type_)
	{
	case OSI_LAYER_2:
	  return "tap";
	case OSI_LAYER_3:
	  return "tun";
	default:
	  return "null";
	}
    }

    const char *str() const
    {
      switch (type_)
	{
	case OSI_LAYER_2:
	  return "OSI_LAYER_2";
	case OSI_LAYER_3:
	  return "OSI_LAYER_3";
	default:
	  return "UNDEF_LAYER";
	}
    }

    bool operator==(const Layer& other)
    {
      return type_ == other.type_;
    }

    bool operator!=(const Layer& other)
    {
      return type_ != other.type_;
    }

  private:
    Type type_;
  };
} // namespace openvpn

#endif // OPENVPN_TUN_LAYER_H
