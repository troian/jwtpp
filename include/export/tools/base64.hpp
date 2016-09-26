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

#pragma once

#include <iostream>
#include <string>
#include <vector>

namespace tools {

/**
 * \brief
 */
class base64 final {
private:
	static const std::string base64_chars;

	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

public:
	/**
	 * \brief
	 *
	 * \param[out]  b64: output data in base64
	 * \param[in]
	 *
	 * \return  None
	 */
	static void encode(std::string &b64, std::vector<uint8_t> &stream);

	/**
	 * \brief
	 *
	 * \param[out]
	 * \param[in]
	 *
	 * \return None
	 */
	static void encode(std::string &b64, const std::string &stream);

	/**
	 * \brief
	 *
	 * \param[out]
	 * \param[in]
	 * \param[in]
	 *
	 * \return None
	 */
    static void encode(std::string &b64, const uint8_t *stream, size_t in_len);

	/**
	 * \brief   Decode base64 string into array. Type T must be any kind of container
	 *
	 * \param[in]  stream: base64 stream
	 *
	 * \return
	 */
	template<typename T>
	static T decode(const std::string &stream) {
		int in_len = stream.size();
		int i = 0;
		int in_ = 0;
		uint8_t array_4[4];
		uint8_t array_3[3];
		T ret;

		while (in_len-- && (stream[in_] != '=') && is_base64(stream[in_])) {
			array_4[i++] = stream[in_];
			in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++) {
					array_4[i] = base64_chars.find(array_4[i]);
				}

				array_3[0] = (array_4[0] << 2) + ((array_4[1] & 0x30) >> 4);
				array_3[1] = ((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2);
				array_3[2] = ((array_4[2] & 0x3) << 6) + array_4[3];

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
				array_4[j] = base64_chars.find(array_4[j]);
			}

			array_3[0] = (array_4[0] << 2) + ((array_4[1] & 0x30) >> 4);
			array_3[1] = ((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2);
			array_3[2] = ((array_4[2] & 0x3) << 6) + array_4[3];

			for (int j = 0; (j < i - 1); j++) {
				ret.push_back(array_3[j]);
			}
		}

		return ret;
	}
};

} // namespace tools
