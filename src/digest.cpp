// The MIT License (MIT)
//
// Copyright (c) 2016-2020 Artur Troian
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

#include <sstream>
#include <iomanip>
#include <cstring>

#include <jwtpp/jwtpp.hh>

#include <openssl/sha.h>

namespace jwtpp {

digest::digest(digest::type type, const uint8_t *in_data, size_t in_size)
	: _size(SHA256_DIGEST_LENGTH)
	, _data(new uint8_t[SHA512_DIGEST_LENGTH], std::default_delete<uint8_t[]>()) {

	switch (type) {
	case digest::type::SHA256: {
		_size = SHA256_DIGEST_LENGTH;
		SHA256_CTX sha_ctx;
		if (SHA256_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA256");
		}

		if (SHA256_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA256_Final(_data.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case digest::type::SHA384: {
		_size = SHA384_DIGEST_LENGTH;
		SHA512_CTX sha_ctx;

		if (SHA384_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA384");
		}

		if (SHA384_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA384_Final(_data.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case digest::type::SHA512: {
		SHA512_CTX sha_ctx;
		_size = SHA512_DIGEST_LENGTH;

		if (SHA512_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA512");
		}

		if (SHA512_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA512_Final(_data.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	}
}

digest::~digest() {
	std::memset(_data.get(), 0, _size);
}

size_t digest::size() const {
	return _size;
}

uint8_t *digest::data() {
	return _data.get();
}

std::string digest::to_string() const {
	std::stringstream s;
	for (size_t i = 0; i < size() / 2; ++i) {
		s << std::hex << std::setfill('0') << std::setw(2) << (_data.get()[i * 2] << 8 | _data.get()[(i * 2) + 1]);
	}

	return s.str();
}

} // namespace jwtpp
