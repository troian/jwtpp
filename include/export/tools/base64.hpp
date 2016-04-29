/**
   \file base64.h

   Copyright (C) 2004-2008 Rene Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   \author Rene Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

#pragma once

#include <iostream>
#include <string>
#include <vector>

namespace tools {

/**
 * \brief
 */
class base64 {
private:
	static const std::string base64_chars;

	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

public:
	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return
	 */
	static std::string encode(std::vector<uint8_t> &stream);
	static std::string encode(const std::string &stream);
    static std::string encode(const uint8_t *stream, size_t in_len);

	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return
	 */
	template<typename T>
	static T decode(std::string const &stream) {
		int in_len = stream.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		unsigned char char_array_4[4], char_array_3[3];
		T ret;

		while (in_len-- && (stream[in_] != '=') && is_base64(stream[in_])) {
			char_array_4[i++] = stream[in_];
			in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++) {
					char_array_4[i] = base64_chars.find(char_array_4[i]);
				}

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++) {
					ret.push_back(char_array_3[i]);
				}

				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 4; j++) {
				char_array_4[j] = 0;
			}

			for (j = 0; j < 4; j++) {
				char_array_4[j] = base64_chars.find(char_array_4[j]);
			}

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++) {
				ret.push_back(char_array_3[j]);
			}
		}

		return ret;
	}
};

} // namespace tools
