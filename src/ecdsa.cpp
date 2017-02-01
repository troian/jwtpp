//
// Created by Artur Troian on 1/28/17.
//
#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>
#include <openssl/err.h>

namespace jose {

ecdsa::ecdsa(jose::alg alg, sp_ecdsa_key key) :
	  crypto(alg)
	, e_(key)
{
	if (alg != jose::alg::ES256 && alg != jose::alg::ES384 && alg != jose::alg::ES512) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

ecdsa::~ecdsa()
{

}

std::string ecdsa::sign(const std::string &data)
{
	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[ECDSA_size(e_.get())], std::default_delete<uint8_t[]>());

	digest d(hash_type_, (const uint8_t *)data.data(), data.length());

	uint32_t sig_len;

	if (ECDSA_sign(0, d.data(), d.size(), sig.get(), &sig_len, e_.get()) != 1) {
		throw std::runtime_error("Couldn't sign ECDSA");
	}

	return std::move(b64::encode_uri(sig.get(), sig_len));
}

bool ecdsa::verify(const std::string &data, const std::string &sig)
{
	digest d(hash_type_, (const uint8_t *)data.data(), data.length());

	std::vector<uint8_t> s = b64::decode_uri(sig.data(), sig.length());

	if (ECDSA_verify(0, d.data(), d.size(), (const uint8_t *)s.data(), s.size(), e_.get()) != 1) {
		ERR_print_errors_fp(stdout);
		return false;
	}

	return true;
}

} // namespace jose
