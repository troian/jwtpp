//
// Created by Artur Troian on 2/1/17.
//

#include <josepp/digest.hpp>

#include <openssl/sha.h>
#include <openssl/md5.h>

namespace jose {

digest::digest(digest::type type, const uint8_t *in_data, size_t in_size)
{
	try {
		data_ = std::shared_ptr<uint8_t>(new uint8_t[SHA512_DIGEST_LENGTH], std::default_delete<uint8_t[]>());
	} catch (...) {
		throw;
	}

	switch (type) {
	case digest::type::SHA256: {
		size_ = SHA256_DIGEST_LENGTH;
		SHA256_CTX sha_ctx;
		if (SHA256_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA256");
		}

		if (SHA256_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA256_Final(data_.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case digest::type::SHA384: {
		size_ = SHA384_DIGEST_LENGTH;
		SHA512_CTX sha_ctx;

		if (SHA384_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA384");
		}

		if (SHA384_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA384_Final(data_.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case digest::type::SHA512: {
		SHA512_CTX sha_ctx;
		size_ = SHA512_DIGEST_LENGTH;

		if (SHA512_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA512");
		}

		if (SHA512_Update(&sha_ctx, in_data, in_size) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA512_Final(data_.get(), &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	}
}

digest::~digest()
{
	std::memset(data_.get(), 0, size_);
}

size_t digest::size() const
{
	return size_;
}

uint8_t *digest::data()
{
	return data_.get();
}

} // namespace jose
