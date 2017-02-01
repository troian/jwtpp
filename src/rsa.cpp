//
// Created by Artur Troian on 1/21/17.
//

#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

#include <openssl/objects.h>
#include <openssl/evp.h>

#include <iostream>
#include <openssl/err.h>

namespace jose {

rsa::rsa(jose::alg alg, sp_rsa_key key) :
	  crypto(alg)
    , r_(key)
{
	if (alg != jose::alg::RS256 && alg != jose::alg::RS384 && alg != jose::alg::RS512) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

rsa::~rsa()
{

}

std::string rsa::sign(const std::string &data)
{
	uint32_t sig_len;

	sig_len = RSA_size(r_.get());
	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[sig_len], std::default_delete<uint8_t[]>());

	digest d(hash_type_, (const uint8_t *)data.data(), data.length());

	if (RSA_sign(hash2nid(hash_type_), d.data(), d.size(), sig.get(), &sig_len, r_.get()) != 1) {
		throw std::runtime_error("Couldn't sign RSA");
	}

	return std::move(b64::encode_uri(sig.get(), sig_len));
}

bool rsa::verify(const std::string &data, const std::string &sig)
{
	digest d(hash_type_, (const uint8_t *)data.data(), data.length());

	std::vector<uint8_t> s = b64::decode_uri(sig.data(), sig.length());

	if (RSA_verify(hash2nid(hash_type_), d.data(), d.size(), (const uint8_t *)s.data(), s.size(), r_.get()) != 1) {
		return false;
	}

	return true;
}

} // namespace jose
