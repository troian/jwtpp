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

public:
	/**
	 * \brief
	 *
	 * \param[out]  b64: output data in base64
	 * \param[in]
	 *
	 * \return  None
	 */
	static void encode(std::string &b64, const std::vector<uint8_t> &stream);

	static void encode(std::string &b64, const std::vector<uint8_t> * const stream);

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
	static void encode(std::string &b64, const uint8_t * const stream, size_t in_len);

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

		while (in_len-- && (stream[in_] != '=') && is_base64((uint8_t)stream[in_])) {
			array_4[i++] = (uint8_t)stream[in_];
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

		return ret;
	}
};

//class b64 final {
//private:
//	using up_bio = typename std::unique_ptr<BIO, decltype(&::BIO_free)>;
//public:
//	static void encode(std::string &out, const uint8_t *const in, size_t in_len)
//	{
//		BIO *bio;
//		BIO *b64;
//		BUF_MEM *bufferPtr;
//
//		b64 = BIO_new(BIO_f_base64());
//		bio = BIO_new(BIO_s_mem());
//		bio = BIO_push(b64, bio);
//
//		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
//		BIO_write(bio, in, in_len);
//		BIO_flush(bio);
//		BIO_get_mem_ptr(bio, &bufferPtr);
//		BIO_set_close(bio, BIO_NOCLOSE);
//		BIO_free_all(bio);
//
//		out.assign(bufferPtr->data, bufferPtr->length);
//	}
//
//	static void encode(std::string &out, std::string const &in)
//	{
//		encode(out, (const uint8_t *)in.data(), in.length());
//	}
//
//	static bool decode(const std::string &in, std::vector<uint8_t> &out)
//	{
//		bool ret = false;
//
//		if (!in.empty()) {
//			BIO *bio, *b64;
//
//			int len = decodeLength(in);
//			std::shared_ptr<uint8_t> buffer = std::shared_ptr<uint8_t>(new uint8_t[len + 1], std::default_delete<uint8_t[]>());
//			if (buffer) {
//				buffer.get()[len] = '\0';
//
//				bio = BIO_new_mem_buf((void *)in.data(), -1);
//				if (bio) {
//					b64 = BIO_new(BIO_f_base64());
//					if (b64) {
//						bio = BIO_push(b64, bio);
//						if (bio) {
//
//							BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
//
//							int out_len = BIO_read(bio, buffer.get(), in.length());
//
//							if (len == out_len) {
//								ret = true;
//								out.clear();
//								out.assign(buffer.get(), buffer.get() + out_len);
//							}
//						}
//					}
//
//					BIO_free_all(bio);
//				}
//			}
//		}
//
//		return ret;
//	}
//
//	static bool decode(const std::string &in, std::string &out)
//	{
//		bool ret = false;
//
//		if (!in.empty()) {
//			BIO *bio, *b64;
//
//			int len = decodeLength(in);
//			std::shared_ptr<uint8_t> buffer = std::shared_ptr<uint8_t>(new uint8_t[len + 1], std::default_delete<uint8_t[]>());
//			if (buffer) {
//				buffer.get()[len] = '\0';
//
//				bio = BIO_new_mem_buf((void *)in.data(), -1);
//				if (bio) {
//					b64 = BIO_new(BIO_f_base64());
//					if (b64) {
//						bio = BIO_push(b64, bio);
//						if (bio) {
//
//							BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
//
//							int out_len = BIO_read(bio, buffer.get(), in.length());
//
//							if (len == out_len) {
//								ret = true;
//								out.clear();
//								out.assign(buffer.get(), buffer.get() + out_len);
//							}
//						}
//					}
//
//					BIO_free_all(bio);
//				}
//			}
//		}
//
//		return ret;
//	}
//
//private:
//	static size_t decodeLength(const std::string &in)
//	{
//		size_t len = in.length();
//		size_t padding = 0;
//
//		if (in[len - 1] == '=' && in[len - 2] == '=') //last two chars are =
//			padding = 2;
//		else if (in[len - 1] == '=') //last char is =
//			padding = 1;
//
//		return (len * 3) / 4 - padding;
//	}
//};

} // namespace jwt
