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

#include <iostream>

#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

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

	sig_len = static_cast<uint32_t>(RSA_size(r_.get()));

	std::shared_ptr<uint8_t> sig = std::shared_ptr<uint8_t>(new uint8_t[sig_len], std::default_delete<uint8_t[]>());

	digest d(hash_type_, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	if (RSA_sign(hash2nid(hash_type_), d.data(), static_cast<int>(d.size()), sig.get(), &sig_len, r_.get()) != 1) {
		throw std::runtime_error("Couldn't sign RSA");
	}

	return std::move(b64::encode_uri(sig.get(), sig_len));
}

bool rsa::verify(const std::string &data, const std::string &sig)
{
	digest d(hash_type_, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	std::vector<uint8_t> s = b64::decode_uri(sig.data(), sig.length());

	return RSA_verify(hash2nid(hash_type_), d.data(), static_cast<int>(d.size()), reinterpret_cast<const uint8_t *>(s.data()), static_cast<int>(s.size()), r_.get()) == 1;

}

} // namespace jose
