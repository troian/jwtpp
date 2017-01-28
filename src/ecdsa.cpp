//
// Created by Artur Troian on 1/28/17.
//
#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>

namespace jwt {

ecdsa::ecdsa(jwt::alg alg, EC_KEY *e) :
	e_(e)
{

}

ecdsa::~ecdsa()
{

}

std::string ecdsa::sign(const std::string &data)
{
	hash_type hash = hash_type::SHA512;

	switch (alg_) {
	case jwt::alg::ES256: {
		hash = hash_type::SHA256;
		break;
	}
	case jwt::alg::ES384: {
		hash = hash_type::SHA384;
		break;
	}
	case jwt::alg::ES512: {
		hash = hash_type::SHA512;
		break;
	}
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[ECDSA_size(e_)], std::default_delete<uint8_t[]>());

	sha2_digest digest(hash, (const uint8_t *)data.data(), data.length());

	uint32_t sig_len;

	if (ECDSA_sign(0, digest.data(), digest.size(), sig.get(), &sig_len, e_) != 1) {
		throw std::runtime_error("Couldn't sign ECDSA");
	}

	return std::move(b64::encode_uri(sig.get(), sig_len));
}

bool ecdsa::verify(const std::string &data, const std::string &sig)
{
	return false;
}

} // namespace jwt
