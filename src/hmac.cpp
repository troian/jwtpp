// The MIT License (MIT)
//
// Copyright (c) 2016 Artur Troian
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

#include <cstring>

#include <josepp/crypto.hpp>
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
	std::memset(const_cast<char *>(secret_.data()), 0 , secret_.length());
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

	HMAC_CTX *hmac;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	HMAC_CTX hmac_l;
	HMAC_CTX_init(&hmac_l);
	hmac = &hmac_l;
#else
	hmac = HMAC_CTX_new();
#endif

	HMAC_Init_ex(hmac, secret_.data(), static_cast<int>(secret_.length()), evp, nullptr);
	HMAC_Update(hmac, reinterpret_cast<const uint8_t *>(data.c_str()), data.size());

	std::shared_ptr<uint8_t> res = std::shared_ptr<uint8_t>(new uint8_t[EVP_MD_size(evp)], std::default_delete<uint8_t[]>());
	uint32_t size;

	HMAC_Final(hmac, res.get(), &size);
	HMAC_CTX_cleanup(hmac);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	HMAC_CTX_free(hmac);
#endif

	return std::move(b64::encode_uri(res.get(), size));
}

bool hmac::verify(const std::string &data, const std::string &sig)
{
	return sig == sign(data);
}

} // namespace jose
