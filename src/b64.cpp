//
// Created by Artur Troian on 1/21/17.
//

#include <josepp/b64.hpp>

namespace jose {

const std::string b64::base64_chars =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void b64::uri_enc(char *buf, size_t len)
{
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
		}
		t++;
	}
}

void b64::uri_dec(char *buf, size_t len)
{
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
		}
		t++;
	}
}

std::string b64::encode(const uint8_t * const stream, size_t in_len)
{
	int i = 0;
	int k = 0;
	uint8_t array_3[3];
	uint8_t array_4[4];
	std::string out;

	while (in_len--) {
		array_3[i++] = stream[k++];
		if (i == 3) {
			array_4[0] = (uint8_t)(array_3[0] & 0xfc) >> 2;
			array_4[1] = (uint8_t)(((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4));
			array_4[2] = (uint8_t)(((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6));
			array_4[3] = (uint8_t)(array_3[2] & 0x3f);

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

		array_4[0] = (uint8_t)((array_3[0] & 0xfc) >> 2);
		array_4[1] = (uint8_t)(((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4));
		array_4[2] = (uint8_t)(((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6));
		array_4[3] = (uint8_t)(array_3[2] & 0x3f);

		for (int j = 0; (j < i + 1); j++) {
			out += base64_chars[array_4[j]];
		}

		while ((i++ < 3)) {
			out += '=';
		}
	}

	return std::move(out);
}

std::string b64::encode(const std::vector<uint8_t> &stream)
{
	return std::move(encode(stream.data(), stream.size()));
}

std::string b64::encode(const std::vector<uint8_t> * const stream)
{
	return std::move(encode(stream->data(), stream->size()));
}

std::string b64::encode(const std::string &stream)
{
	return std::move(encode(reinterpret_cast<const uint8_t *>(stream.c_str()), stream.size()));
}

std::string b64::encode_uri(const uint8_t * const stream, size_t in_len)
{
	std::string out = encode(stream, in_len);
	uri_enc((char *)out.data(), out.length());

	return std::move(out);
}

std::string b64::encode_uri(const std::string &stream)
{
	return std::move(encode_uri((const uint8_t *)stream.data(), stream.length()));
}

std::string b64::encode_uri(const std::vector<uint8_t> &stream)
{
	return std::move(encode_uri((const uint8_t *)stream.data(), stream.size()));
}

std::string b64::encode_uri(const std::vector<uint8_t> * const stream)
{
	return std::move(encode_uri((const uint8_t *)stream->data(), stream->size()));
}

std::vector<uint8_t> b64::decode(const char *in, size_t in_size)
{
	int         in_len = in_size;
	int         i = 0;
	int         in_ = 0;
	uint8_t     array_4[4];
	uint8_t     array_3[3];
	std::vector<uint8_t> ret;

	while (in_len-- && (in[in_] != '=') && is_base64((uint8_t)in[in_])) {
		array_4[i++] = (uint8_t)in[in_];
		in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				array_4[i] = (uint8_t)base64_chars.find(array_4[i]);
			}

			array_3[0] = (uint8_t)((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
			array_3[1] = (uint8_t)(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2));
			array_3[2] = (uint8_t)(((array_4[2] & 0x3) << 6) + array_4[3]);

			for (i = 0; (i < 3); i++) {
				ret.push_back(array_3[i]);
			}

			i = 0;
		}
	}

	if (i) {
		for (int j = i; j < 4; j++) {
			array_4[j] = 0;
		}

		for (int j = 0; j < 4; j++) {
			array_4[j] = (uint8_t)base64_chars.find(array_4[j]);
		}

		array_3[0] = (uint8_t)((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
		array_3[1] = (uint8_t)((uint8_t)(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2)));
		array_3[2] = (uint8_t)((uint8_t)(((array_4[2] & 0x3) << 6) + array_4[3]));

		for (int j = 0; (j < i - 1); j++) {
			ret.push_back(array_3[j]);
		}
	}

	return std::move(ret);
}

std::string b64::decode(const std::string &in)
{
	std::vector<uint8_t> tmp = decode(in.data(), in.length());
	return std::move(std::string(tmp.data(), tmp.data() + tmp.size()));
}

std::string b64::decode_uri(const std::string &in)
{
	std::string tmp(in);
	uri_dec((char *)tmp.data(), tmp.length());

	std::vector<uint8_t> tmpd = decode(tmp.data(), tmp.length());
	return std::move(std::string(tmpd.data(), tmpd.data() + tmpd.size()));
}

std::vector<uint8_t> b64::decode_uri(const char *in, size_t in_size)
{
	std::string tmp(in, in_size);
	uri_dec((char *)tmp.data(), tmp.length());

	return std::move(decode(tmp.data(), tmp.length()));
}

} // namespace jose
