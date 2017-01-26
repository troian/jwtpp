//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <memory>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace jwt {

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
	static std::string decode(const std::string &in);
	static std::string decode_uri(const std::string &in);

//	/**
//	 * \brief   Decode base64 string into array. Type T must be any kind of container
//	 *
//	 * \param[in]  stream: base64 stream
//	 *
//	 * \return
//	 */
//	template<typename T>
//	static T decode(const std::string &stream) {
//		int in_len = stream.size();
//		int i = 0;
//		int in_ = 0;
//		uint8_t array_4[4];
//		uint8_t array_3[3];
//		T ret;
//
//		while (in_len-- && (stream[in_] != '=') && is_base64((uint8_t)stream[in_])) {
//			array_4[i++] = (uint8_t)stream[in_];
//			in_++;
//			if (i == 4) {
//				for (i = 0; i < 4; i++) {
//					array_4[i] = (uint8_t)base64_chars.find(array_4[i]);
//				}
//
//				array_3[0] = (uint8_t)((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
//				array_3[1] = (uint8_t)(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2));
//				array_3[2] = (uint8_t)(((array_4[2] & 0x3) << 6) + array_4[3]);
//
//				for (i = 0; (i < 3); i++) {
//					ret.push_back(array_3[i]);
//				}
//
//				i = 0;
//			}
//		}
//
//		if (i) {
//			for (int j = i; j < 4; j++) {
//				array_4[j] = 0;
//			}
//
//			for (int j = 0; j < 4; j++) {
//				array_4[j] = (uint8_t)base64_chars.find(array_4[j]);
//			}
//
//			array_3[0] = (uint8_t)((array_4[0] << 2) + ((array_4[1] & 0x30) >> 4));
//			array_3[1] = (uint8_t)((uint8_t)(((array_4[1] & 0xf) << 4) + ((array_4[2] & 0x3c) >> 2)));
//			array_3[2] = (uint8_t)((uint8_t)(((array_4[2] & 0x3) << 6) + array_4[3]));
//
//			for (int j = 0; (j < i - 1); j++) {
//				ret.push_back(array_3[j]);
//			}
//		}
//
//		return ret;
//	}
};

} // namespace jwt
