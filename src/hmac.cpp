//
// Created by Artur Troian on 1/21/17.
//

#include <cstring>

#include <josepp/crypto.hpp>

#include <openssl/hmac.h>

#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

namespace jwt {

hmac::hmac(jwt::alg alg, const std::string &secret) :
	  crypto(alg)
	, secret_(secret)
{
	if (alg != jwt::alg::HS256 && alg != jwt::alg::HS384 && alg != jwt::alg::HS512) {
		throw std::invalid_argument("Invalid algorithm");
	}

	if (secret.empty()) {
		throw std::invalid_argument("Invalid secret");
	}
}

hmac::~hmac()
{
	// clear out secret
	std::memset((void *)secret_.data(), 0 , secret_.length());
}

std::string hmac::sign(const std::string &data)
{
	if (data.empty()) {
		throw std::invalid_argument("Data is empty");
	}

	const EVP_MD *alg;

	switch (alg_) {
	case jwt::alg::HS256:
		alg = EVP_sha256();
		break;
	case jwt::alg::HS384:
		alg = EVP_sha384();
		break;
	case jwt::alg::HS512:
		alg = EVP_sha512();
		break;
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	uint32_t size;

	HMAC(alg, secret_.data(), secret_.length(), (const uint8_t *) data.c_str(), data.size(), nullptr, &size);

	std::shared_ptr<uint8_t> res = std::shared_ptr<uint8_t>(new uint8_t[size], std::default_delete<uint8_t[]>());

	HMAC(alg, secret_.data(), secret_.length(), (const uint8_t *) data.c_str(), data.size(), res.get(), &size);

	return std::move(b64::encode_uri(res.get(), size));
}

bool hmac::verify(const std::string &data, const std::string &sig)
{
	return sig == sign(data);
}

} // namespace jwt
