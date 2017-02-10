// The MIT License (MIT)
//
// Copyright (c) 2016 Artur Troian
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

#include <memory>
#include <string>
#include <vector>

namespace jose {

/**
 * \brief
 */
class b64 final {
private:
	static const std::string base64_chars;

	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

	static void uri_enc(char *buf, size_t len);

	static void uri_dec(char *buf, size_t len);

public:
	/**
	 * \brief
	 *
	 * \param[out]  b64: output data in base64
	 * \param[in]
	 *
	 * \return  None
	 */
	static std::string encode(const uint8_t * const stream, size_t in_len);
	static std::string encode(const std::vector<uint8_t> &stream);
	static std::string encode(const std::vector<uint8_t> * const stream);
	static std::string encode(const std::string &stream);

	static std::string encode_uri(const uint8_t * const stream, size_t in_len);
	static std::string encode_uri(const std::string &stream);
	static std::string encode_uri(const std::vector<uint8_t> &stream);
	static std::string encode_uri(const std::vector<uint8_t> * const stream);

	static std::vector<uint8_t> decode(const char *in, size_t in_size);
	static std::vector<uint8_t> decode_uri(const char *in, size_t in_size);
	static std::string decode(const std::string &in);
	static std::string decode_uri(const std::string &in);
};

} // namespace jose
