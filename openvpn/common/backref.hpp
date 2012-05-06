#ifndef OPENVPN_COMMON_BACKREF_H
#define OPENVPN_COMMON_BACKREF_H

namespace openvpn {

  template <typename REF>
  class BackRef {
  public:
    BackRef() { reset(); }

    bool defined() const
    {
      return ref_ != NULL;
    }

    void reset()
    {
      ref_ = NULL;
      value_ = NULL;
    }

    void set(REF* ref, void* value)
    {
      ref_ = ref;
      value_ = value;
    }

    void set_ref(REF* ref)
    {
      ref_ = ref;
    }

    void set_value(void* value)
    {
      value_ = value;
    }

    template <typename VALUE>
    VALUE* value() const
    {
      return (VALUE*)value_;
    }

    REF* ref() const { return ref_; }

  private:
    REF* ref_;
    void* value_;
  };

}

#endif
