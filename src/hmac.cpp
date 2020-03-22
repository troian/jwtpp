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

#include <openssl/hmac.h>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

hmac::hmac(const secure_string &secret, alg_t a)
	: crypto(a)
	, _secret(secret)
{
	if (a != alg_t::HS256 && a != alg_t::HS384 && a != alg_t::HS512) {
		throw std::invalid_argument("Invalid algorithm");
	}

	if (secret.empty()) {
		throw std::invalid_argument("Invalid secret");
	}
}

std::string hmac::sign(const std::string &data) {
	if (data.empty()) {
		throw std::invalid_argument("data is empty");
	}

	const EVP_MD *evp;

	switch (_alg) {
	case alg_t::HS256: evp = EVP_sha256(); break;
	case alg_t::HS384: evp = EVP_sha384(); break;
	case alg_t::HS512: evp = EVP_sha512(); break;
	default:
		// Should never happen
		throw std::runtime_error("Invalid alg");
	}

	HMAC_CTX *hmac;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX hmac_l;
	HMAC_CTX_init(&hmac_l);
	hmac = &hmac_l;
#else
	hmac = HMAC_CTX_new();
#endif

	HMAC_Init_ex(hmac, _secret.data(), static_cast<int>(_secret.length()), evp, nullptr);
	HMAC_Update(hmac, reinterpret_cast<const uint8_t *>(data.c_str()), data.size());

	auto res = std::shared_ptr<uint8_t>(new uint8_t[EVP_MD_size(evp)], std::default_delete<uint8_t[]>());
	uint32_t size;

	HMAC_Final(hmac, res.get(), &size);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX_cleanup(hmac);
#else
	HMAC_CTX_free(hmac);
#endif

	return b64::encode_uri(res.get(), size);
}

bool hmac::verify(const std::string &data, const std::string &sig) {
	return sig == sign(data);
}

} // namespace jwtpp
