//
// Created by Artur Troian on 2019-08-14
//

#include <iostream>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

pss::pss(sp_rsa_key key, alg_t a)
	: crypto(a)
	, _r(key)
{
	if (a != alg_t::PS256 && a != alg_t::PS384 && a != alg_t::PS512) {
		throw std::invalid_argument("Invalid algorithm");
	}

	_key_size = static_cast<size_t>(RSA_size(_r.get()));

	if (_alg == alg_t::PS512 && (_key_size < 256)) {
		throw std::runtime_error("insufficient key size");
	}
}

std::string pss::sign(const std::string &data) {
	if (data.empty()) {
		throw std::invalid_argument("data is empty");
	}

	digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	auto padded = std::shared_ptr<uint8_t>(new uint8_t[_key_size], std::default_delete<uint8_t[]>());

	auto sig = std::shared_ptr<uint8_t>(new uint8_t[_key_size], std::default_delete<uint8_t[]>());

	if (RSA_padding_add_PKCS1_PSS(_r.get(), padded.get(), d.data(), digest::md(_hash_type), -1) != 1) {
		throw std::runtime_error("failed to create signature");
	}

	if (RSA_private_encrypt(_key_size, padded.get(), sig.get(), _r.get(), RSA_NO_PADDING) < 0) {
		throw std::runtime_error("couldn't sign RSA");
	}

	return b64::encode_uri(sig.get(), _key_size);
}

bool pss::verify(const std::string &data, const std::string &sig) {
	digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	auto decrypted_sig = std::shared_ptr<uint8_t>(new uint8_t[_key_size], std::default_delete<uint8_t[]>());
	auto decoded_sig = b64::decode_uri(sig.data(), sig.length());

	if(RSA_public_decrypt(decoded_sig.size(), decoded_sig.data(), decrypted_sig.get(), _r.get(), RSA_NO_PADDING) < 0) {
		throw std::runtime_error("invalid signature");
	}

	return RSA_verify_PKCS1_PSS(_r.get(), d.data(), digest::md(_hash_type), decrypted_sig.get(), -1) == 1;
}

} // namespace jwtpp
