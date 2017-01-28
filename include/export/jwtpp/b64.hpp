//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <memory>
#include <string>
#include <vector>

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
};

} // namespace jwt
