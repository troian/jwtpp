//
// Created by Artur Troian on 1/21/17.
//

#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

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
	uint32_t type = NID_sha512;
	hash_type hash = hash_type::SHA512;

	switch (alg_) {
	case jwt::alg::RS256: {
		type = NID_sha256;
		hash = hash_type::SHA256;
		break;
	}
	case jwt::alg::RS384: {
		type = NID_sha384;
		hash = hash_type::SHA384;
		break;
	}
	case jwt::alg::RS512: {
		type = NID_sha512;
		hash = hash_type::SHA512;
		break;
	}
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	uint32_t sig_len;

	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[RSA_size(r_)], std::default_delete<uint8_t[]>());

	sha2_digest digest(hash, (const uint8_t *)data.data(), data.length());
	if (RSA_sign(type, digest.data(), digest.size(), sig.get(), &sig_len, r_) != 1) {
		throw std::runtime_error("Couldn't sign RSA");
	}

	return std::move(b64::encode_uri(sig.get(), sig_len));
}

bool rsa::verify(const std::string &data, const std::string &sig)
{
	return sig == sign(data);
}

} // namespace jwt
