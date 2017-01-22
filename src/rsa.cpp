//
// Created by Artur Troian on 1/21/17.
//

#include <jwtpp/crypto.hpp>
#include <jwtpp/b64.hpp>

#include <openssl/sha.h>
#include <openssl/objects.h>

namespace jwt {

rsa::rsa(jwt::alg alg, RSA *r) :
	  crypto(alg)
	, r_(r)
{
	if (alg != jwt::alg::RS256 && alg != jwt::alg::RS384 && alg != jwt::alg::RS512) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

rsa::~rsa()
{

}

std::string rsa::sign(const std::string &data)
{
	uint8_t digest[SHA512_DIGEST_LENGTH];
	uint32_t digest_len = SHA512_DIGEST_LENGTH;

	uint32_t type = NID_sha512;

	std::string signature;

	switch (alg_) {
	case jwt::alg::RS256: {
		SHA256_CTX sha_ctx;

		digest_len = SHA256_DIGEST_LENGTH;
		type = NID_sha256;

		if (SHA256_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA256");
		}

		if (SHA256_Update(&sha_ctx, (const uint8_t *)data.c_str(), data.size()) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA256_Final(digest, &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case jwt::alg::RS384: {
		SHA512_CTX sha_ctx;

		digest_len = SHA384_DIGEST_LENGTH;
		type = NID_sha384;

		if (SHA384_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA256");
		}

		if (SHA384_Update(&sha_ctx, (const uint8_t *)data.c_str(), data.size()) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA384_Final(digest, &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	case jwt::alg::RS512: {
		SHA512_CTX sha_ctx;

		digest_len = SHA512_DIGEST_LENGTH;
		type = NID_sha512;

		if (SHA512_Init(&sha_ctx) != 1) {
			throw std::runtime_error("Couldn't init SHA256");
		}

		if (SHA512_Update(&sha_ctx, (const uint8_t *)data.c_str(), data.size()) != 1) {
			throw std::runtime_error("Couldn't calculate hash");
		}

		if (SHA512_Final(digest, &sha_ctx) != 1) {
			throw std::runtime_error("Couldn't finalize SHA");
		}
		break;
	}
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	uint32_t sig_len;

	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[RSA_size(r_)], std::default_delete<uint8_t[]>());

	if (RSA_sign(type, digest, digest_len, sig.get(), &sig_len, r_) != 1) {
		throw std::runtime_error("Couldn't sign RSA");
	}

	b64::encode(signature, sig.get(), sig_len);

	return signature;
}

bool rsa::verify(const std::string &data, const std::string &sig)
{
	return sig == sign(data);
}

} // namespace jwt
