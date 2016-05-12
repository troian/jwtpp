/**
 * Copyright (C) 2004-2008 Rene Nyffenegger
 *
 * This source code is provided 'as-is', without any express or implied
 * warranty. In no event will the author be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this source code must not be misrepresented; you must not
 *    claim that you wrote the original source code. If you use this source code
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 *
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original source code.
 *
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * \author Rene Nyffenegger rene.nyffenegger@adp-gmbh.ch
 * \author Artur Troian troian.ap@gmail.com
 */

#include <iostream>
#include <string>

#include <tools/base64.hpp>

namespace tools {
const std::string base64::base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

void base64::encode(std::string &b64, const uint8_t *stream, size_t in_len)
{
	int i = 0;
	int j = 0;
	int k = 0;
	uint8_t array_3[3];
	uint8_t array_4[4];

	while (in_len--) {
		array_3[i++] = stream[k++];
		if (i == 3) {
			array_4[0] = (array_3[0] & 0xfc) >> 2;
			array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
			array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
			array_4[3] = array_3[2] & 0x3f;

			for (i = 0; (i < 4); i++) {
				b64 += base64_chars[array_4[i]];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++) {
			array_3[j] = '\0';
		}

		array_4[0] = (array_3[0] & 0xfc) >> 2;
		array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
		array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
		array_4[3] = array_3[2] & 0x3f;

		for (j = 0; (j < i + 1); j++) {
			b64 += base64_chars[array_4[j]];
		}

		while ((i++ < 3)) {
			b64 += '=';
		}

	}
}

void base64::encode(std::string &b64, std::vector<uint8_t> &stream)
{
	encode(b64, reinterpret_cast<const uint8_t *>(stream.data()), stream.size());
}

void base64::encode(std::string &b64, const std::string &stream)
{
	encode(b64, reinterpret_cast<const uint8_t *>(stream.c_str()), stream.size());
}

} // namespace tools
