//
// Created by Artur Troian on 4/29/18.
//

#pragma once

#include <openssl/crypto.h>
#include <string>

namespace jose {

template <class T>
class secure_allocator : public std::allocator<T> {
public:
	template<class U> struct rebind {
		typedef secure_allocator<U> other;
	};

	secure_allocator() noexcept {}

	secure_allocator(const secure_allocator&) noexcept {}

	template <class U>
	explicit secure_allocator(const secure_allocator<U>&) noexcept {}

	void deallocate(T *p, std::size_t n) noexcept {
		OPENSSL_cleanse(p, n);
		std::allocator<T>::deallocate(p, n);
	}
};

using secure_string = std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

}