//
// Created by Artur Troian on 1/21/17.
//

#include <jwtpp/b64.hpp>

namespace jwt {

const std::string b64::base64_chars =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

void b64::encode(std::string &b64, const uint8_t * const stream, size_t in_len)
{
	int i = 0;
	int k = 0;
	uint8_t array_3[3];
	uint8_t array_4[4];

	while (in_len--) {
		array_3[i++] = stream[k++];
		if (i == 3) {
			array_4[0] = (uint8_t)(array_3[0] & 0xfc) >> 2;
			array_4[1] = (uint8_t)(((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4));
			array_4[2] = (uint8_t)(((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6));
			array_4[3] = (uint8_t)(array_3[2] & 0x3f);

			for (i = 0; (i < 4); i++) {
				b64 += base64_chars[array_4[i]];
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
			b64 += base64_chars[array_4[j]];
		}

		while ((i++ < 3)) {
			b64 += '=';
		}

	}
}

void b64::encode(std::string &b64, const std::vector<uint8_t> &stream)
{
	encode(b64, stream.data(), stream.size());
}

void b64::encode(std::string &b64, const std::vector<uint8_t> * const stream)
{
	encode(b64, stream->data(), stream->size());
}

void b64::encode(std::string &b64, const std::string &stream)
{
	encode(b64, reinterpret_cast<const uint8_t *>(stream.c_str()), stream.size());
}

}
