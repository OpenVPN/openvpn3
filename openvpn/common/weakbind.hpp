#ifndef OPENVPN_COMMON_WEAKBIND_H
#define OPENVPN_COMMON_WEAKBIND_H

#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>

namespace openvpn {

  template< typename T >
  class from_weak_impl {
  public:    // result_type must defined and be const,
    // we must return a strong ptr to prevent another thread unlocking between calls
    typedef const boost::shared_ptr< T> result_type; 
    inline from_weak_impl( const boost::weak_ptr< T> &p0) : p( p0)  {   }
    inline from_weak_impl( const boost::shared_ptr< T> &p0) : p( p0)  {   }

    inline result_type operator ()() const
    {
      return boost::shared_ptr<T>(p);
    }

  private:
    boost::weak_ptr< T> p; 
  };

  template<class T>
  inline from_weak_impl< T>
  from_weak(  const boost::weak_ptr<T> & p)
  {
    return from_weak_impl< T>( p);
  }

  template<class T>
  inline from_weak_impl< T>
  from_weak(  const boost::shared_ptr<T> & p)
  {
    return from_weak_impl< T>( p);
  }

} // namespace openvpn

#endif // OPENVPN_COMMON_WEAKBIND_H
