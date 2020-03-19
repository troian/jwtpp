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

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

const std::string b64::base64_chars =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void b64::uri_enc(char *buf, size_t len) {
	size_t i, t;

	for (i = t = 0; i < len; i++) {
		switch (buf[i]) {
		case '+':
			buf[t] = '-';
			break;
		case '/':
			buf[t] = '_';
			break;
		case '=':
			continue;
		default:
			break;
		}
		t++;
	}
}

void b64::uri_dec(char *buf, size_t len) {
	size_t i, t;

	for (i = t = 0; i < len; i++) {
		switch (buf[i]) {
		case '-':
			buf[t] = '+';
			break;
		case '_':
			buf[t] = '/';
			break;
		case '=':
			continue;
		default:
			break;
		}
		t++;
	}
}

std::string b64::encode(const uint8_t * const stream, size_t in_len) {
	int i = 0;
	int k = 0;
	uint8_t array_3[3];
	uint8_t array_4[4];
	std::string out;

	while (in_len--) {
		array_3[i++] = stream[k++];
		if (i == 3) {
			array_4[0] = static_cast<uint8_t>((array_3[0] & 0xfc) >> 2);
			array_4[1] = static_cast<uint8_t>((((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4)));
			array_4[2] = static_cast<uint8_t>((((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6)));
			array_4[3] = static_cast<uint8_t>((array_3[2] & 0x3f));

			for (i = 0; (i < 4); i++) {
				out += base64_chars[array_4[i]];
			}
			i = 0;
		}
	}

	if (i) {
		for (int j = i; j < 3; j++) {
			array_3[j] = '\0';
		}

		array_4[0] = static_cast<uint8_t>(((array_3[0] & 0xfc) >> 2));
		array_4[1] = static_cast<uint8_t>((((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4)));
		array_4[2] = static_cast<uint8_t>((((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6)));
		array_4[3] = static_cast<uint8_t>((array_3[2] & 0x3f));

		for (int j = 0; (j < i + 1); j++) {
			out += base64_chars[array_4[j]];
		}

//		while ((i++ < 3)) {
//			out += '=';
//		}
	}

	return out;
}

std::string b64::encode(const std::vector<uint8_t> &stream) {
	return encode(stream.data(), stream.size());
}

std::string b64::encode(const std::vector<uint8_t> * const stream) {
	return encode(stream->data(), stream->size());
}

std::string b64::encode(const std::string &stream) {
	return encode(reinterpret_cast<const uint8_t *>(stream.c_str()), stream.size());
}

std::string b64::encode_uri(const uint8_t * const stream, size_t in_len) {
	std::string out = encode(stream, in_len);
	uri_enc(const_cast<char *>(out.data()), out.length());

	return out;
}

std::string b64::encode_uri(const std::string &stream) {
	return encode_uri(reinterpret_cast<const uint8_t *>(stream.data()), stream.length());
}

std::string b64::encode_uri(const std::vector<uint8_t> &stream) {
	return encode_uri(stream.data(), stream.size());
}

std::string b64::encode_uri(const std::vector<uint8_t> * const stream) {
	return encode_uri(stream->data(), stream->size());
}

std::vector<uint8_t> b64::decode(const char *in, size_t in_size) {
	size_t      in_len = in_size;
	size_t      i = 0;
	size_t      in_ = 0;
	uint8_t     array_4[4];
	uint8_t     array_3[3];
	std::vector<uint8_t> ret;

	while (in_len-- && (in[in_] != '=') && is_base64(static_cast<uint8_t>(in[in_]))) {
		array_4[i++] = static_cast<uint8_t>(in[in_]);
		in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				array_4[i] = static_cast<uint8_t>(base64_chars.find(array_4[i]));
			}

			array_3[0] = static_cast<uint8_t>((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
			array_3[1] = static_cast<uint8_t>(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2));
			array_3[2] = static_cast<uint8_t>(((array_4[2] & 0x3) << 6) + array_4[3]);

			for (i = 0; (i < 3); i++) {
				ret.push_back(array_3[i]);
			}

			i = 0;
		}
	}

	if (i) {
		for (size_t j = i; j < 4; j++) {
			array_4[j] = 0;
		}

		for (size_t j = 0; j < 4; j++) {
			array_4[j] = static_cast<uint8_t>(base64_chars.find(array_4[j]));
		}

		array_3[0] = static_cast<uint8_t>((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
		array_3[1] = static_cast<uint8_t>(static_cast<uint8_t>(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2)));
		array_3[2] = static_cast<uint8_t>(static_cast<uint8_t>(((array_4[2] & 0x3) << 6) + array_4[3]));

		for (size_t j = 0; (j < i - 1); j++) {
			ret.push_back(array_3[j]);
		}
	}

	return ret;
}

std::string b64::decode(const std::string &in) {
	std::vector<uint8_t> tmp = decode(in.data(), in.length());
	return std::string(tmp.data(), tmp.data() + tmp.size());
}

std::string b64::decode_uri(const std::string &in) {
	std::string tmp(in);
	uri_dec(const_cast<char *>(tmp.data()), tmp.length());

	std::vector<uint8_t> tmpd = decode(tmp.data(), tmp.length());
	return std::string(tmpd.data(), tmpd.data() + tmpd.size());
}

std::vector<uint8_t> b64::decode_uri(const char *in, size_t in_size) {
	std::string tmp(in, in_size);
	uri_dec(const_cast<char *>(tmp.data()), tmp.length());

	return decode(tmp.data(), tmp.length());
}

} // namespace jwtpp
