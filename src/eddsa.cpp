// The MIT License (MIT)
//
// Copyright (c) 2016-2020 Artur Troian
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <jwtpp/jwtpp.hh>

#if defined(JWTPP_SUPPORTED_EDDSA)
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

namespace jwtpp {

eddsa::eddsa(sp_evp_key key, alg_t a)
	: crypto(a)
	, _e(key)
{
	if (a != alg_t::EdDSA) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

std::string eddsa::sign(const std::string &data) {
	if (data.empty()) {
		throw std::invalid_argument("data is empty");
	}

	auto md = sp_evp_md_ctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);

	EVP_MD_CTX_init(md.get());

	if (EVP_DigestSignInit(md.get(), nullptr, nullptr, nullptr, _e.get()) != 1) {
		throw std::runtime_error("eddsa: digest sign init");
	}

	size_t sig_len = EVP_PKEY_size(_e.get());

	auto sig = std::shared_ptr<uint8_t>(new uint8_t[sig_len], std::default_delete<uint8_t[]>());

	if (EVP_DigestSign(md.get(), sig.get(), &sig_len, (const uint8_t *)data.data(), data.size()) != 1) {
		throw std::runtime_error("eddsa: digest sign");
	}

	return b64::encode_uri(sig.get(), sig_len);
}

bool eddsa::verify(const std::string &data, const std::string &sig) {
	auto s = b64::decode_uri(sig.data(), sig.length());

	auto md = sp_evp_md_ctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);

	EVP_MD_CTX_init(md.get());

	if (EVP_DigestVerifyInit(md.get(), nullptr, nullptr, nullptr, _e.get()) != 1) {
		throw std::runtime_error("eddsa: digest verify init");
	}

	return EVP_DigestVerify(md.get(), s.data(), s.size(), (const uint8_t *)data.data(), data.size()) == 1;
}

sp_evp_key eddsa::gen() {
	auto ctx = sp_evp_pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), ::EVP_PKEY_CTX_free);
	if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
		throw std::runtime_error("eddsa: couldn't init evp keygen");
	}

	EVP_PKEY *key = nullptr;

	if (EVP_PKEY_keygen(ctx.get(), &key) != 1) {
		throw std::runtime_error("eddsa: couldn't generate ED25519 key");
	}

	return sp_evp_key(key, ::EVP_PKEY_free);
}

sp_evp_key eddsa::get_pub(sp_evp_key priv) {
	size_t key_len;

	if (EVP_PKEY_get_raw_public_key(priv.get(), nullptr, &key_len) != 1) {
		throw std::runtime_error("eddsa: couldn't read size of public key");
	}

	auto k = std::shared_ptr<uint8_t>(new uint8_t[key_len], std::default_delete<uint8_t[]>());

	if (EVP_PKEY_get_raw_public_key(priv.get(), k.get(), &key_len) != 1) {
		throw std::runtime_error("eddsa: couldn't extract public key");
	}

	return sp_evp_key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, k.get(), key_len), ::EVP_PKEY_free);
}

} // namespace jwtpp

#endif // defined(JWTPP_SUPPORTED_EDDSA)
