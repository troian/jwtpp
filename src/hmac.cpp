//
// Created by Artur Troian on 1/21/17.
//

#include <cstring>

#include <josepp/crypto.hpp>

#include <openssl/hmac.h>

#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

namespace jose {

hmac::hmac(jose::alg alg, const std::string &secret) :
	  crypto(alg)
	, secret_(secret)
{
	if (alg != jose::alg::HS256 && alg != jose::alg::HS384 && alg != jose::alg::HS512) {
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

	const EVP_MD *evp;

	switch (alg_) {
	case jose::alg::HS256: evp = EVP_sha256(); break;
	case jose::alg::HS384: evp = EVP_sha384(); break;
	case jose::alg::HS512: evp = EVP_sha512(); break;
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	HMAC_CTX hmac;
	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, secret_.data(), secret_.length(), evp, NULL);
	HMAC_Update(&hmac, (const uint8_t *)data.c_str(), data.size());

	std::shared_ptr<uint8_t> res = std::shared_ptr<uint8_t>(new uint8_t[EVP_MD_size(evp)], std::default_delete<uint8_t[]>());
	uint32_t size;

	HMAC_Final(&hmac, res.get(), &size);
	HMAC_CTX_cleanup(&hmac);

	return std::move(b64::encode_uri(res.get(), size));
}

bool hmac::verify(const std::string &data, const std::string &sig)
{
	return sig == sign(data);
}

} // namespace jose
