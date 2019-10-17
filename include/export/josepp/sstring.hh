// The MIT License (MIT)
//
// Copyright (c) 2019 Artur Troian
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#pragma once

#include <openssl/crypto.h>
#include <string>

namespace jose {

template <class T>
class secure_allocator : public std::allocator<T> {
public:
	template <class U>
	struct rebind {
		typedef secure_allocator<U> other;
	};

	secure_allocator() noexcept = default;

	secure_allocator(const secure_allocator &) noexcept {}

	template <class U>
	explicit secure_allocator(const secure_allocator<U> &) noexcept {}

	void deallocate(T *p, std::size_t n) noexcept {
		OPENSSL_cleanse(p, n);
		std::allocator<T>::deallocate(p, n);
	}
};

using secure_string = std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

} // namespace jose
