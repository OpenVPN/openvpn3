//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// High-performance functor with move-only semantics.

#ifndef OPENVPN_COMMON_FUNCTION_H
#define OPENVPN_COMMON_FUNCTION_H

#include <new>
#include <utility>

namespace openvpn {
  template <typename F>
  class Function;

  template <typename R, typename ... A>
  class Function<R(A...)>
  {
  public:
    static constexpr size_t N = 3; // max size of functor in machine words

    template <typename T>
    Function(T&& functor) noexcept
    {
      static_assert(sizeof(Intern<T>) <= sizeof(data), "Functor too large");
      setup_methods<T>();
      new (data) Intern<T>(std::move(functor));
    }

    Function(Function&& f) noexcept
    {
      methods = f.methods;
      methods->move(data, f.data);
    }

    ~Function()
    {
      methods->destruct(data);
    }

    R operator()(A... args)
    {
      return methods->invoke(data, args...);
    }

  private:
    struct Methods
    {
      R (*invoke)(void *, A...);
      void (*move)(void *, void *);
      void (*destruct)(void *);
    };

    template <typename T>
    void setup_methods()
    {
      static const struct Methods m = {
	&Intern<T>::invoke,
	&Intern<T>::move,
	&Intern<T>::destruct,
      };
      methods = &m;
    }

    template <typename T>
    class Intern
    {
    public:
      Intern(Intern&& obj) noexcept
        : functor_(std::move(obj.functor_))
      {
      }

      Intern(T&& functor) noexcept
        : functor_(std::move(functor))
      {
      }

      static R invoke(void *ptr, A... args)
      {
	Intern* self = reinterpret_cast<Intern<T>*>(ptr);
	return self->functor_(args...);
      }

      static void move(void *dest, void *src)
      {
	Intern* s = reinterpret_cast<Intern<T>*>(src);
	new (dest) Intern(std::move(*s));
      }

      static void destruct(void *ptr)
      {
	Intern* self = reinterpret_cast<Intern<T>*>(ptr);
	self->~Intern();
      }

    private:
      T functor_;
    };

    const Methods* methods;
    void* data[N];
  };
}

#endif
