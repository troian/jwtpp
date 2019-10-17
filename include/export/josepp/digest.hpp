//
// Created by Artur Troian on 2/1/17.
//
#pragma once

#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>

#if defined(_MSC_VER) && (_MSC_VER < 1700)
#define final
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

namespace jose {

/**
 * \brief
 */
class digest final {
public:
#if defined(_MSC_VER) && (_MSC_VER < 1700)
	enum type {
#else
	enum class type {
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)
		SHA256,
		SHA384,
		SHA512
	};

public:
	digest(digest::type type, const uint8_t *in_data, size_t in_size);
	~digest();

	size_t size() const;

	uint8_t *data();

	std::string to_string() const;

public:
	static const EVP_MD *md(digest::type t) {
		switch (t) {
		case type::SHA256:
			return EVP_sha256();
		case type::SHA384:
			return EVP_sha384();
		case type::SHA512:
			return EVP_sha512();
		}
	}

private:
	size_t                   _size;
	std::shared_ptr<uint8_t> _data;
};

} // namespace jose
