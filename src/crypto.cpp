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

namespace jwtpp {

crypto::crypto(alg_t a)
	: _alg(a)
	, _hdr()
	, _hash_type(digest::type::SHA256)
{
	if (a == alg_t::HS256 || a == alg_t::RS256 || a == alg_t::ES256 || a == alg_t::PS256) {
		_hash_type = digest::type::SHA256;
	} else if (a == alg_t::HS384 || a == alg_t::RS384 || a == alg_t::ES384 || a == alg_t::PS384) {
		_hash_type = digest::type::SHA384;
	} else if (a == alg_t::HS512 || a == alg_t::RS512 || a == alg_t::ES512 || a == alg_t::PS512) {
		_hash_type = digest::type::SHA512;
#if defined(JWTPP_SUPPORTED_EDDSA)
	} else if (a == alg_t::EdDSA) {
		// ED25519 does not support digests
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	} else {
		throw std::runtime_error("invalid algorithm");
	}
}

crypto::~crypto() {}

const char *crypto::alg2str(alg_t a) {
	switch (a) {
	case alg_t::NONE:
		return "none";
	case alg_t::HS256:
		return "HS256";
	case alg_t::HS384:
		return "HS384";
	case alg_t::HS512:
		return "HS512";
	case alg_t::RS256:
		return "RS256";
	case alg_t::RS384:
		return "RS384";
	case alg_t::RS512:
		return "RS512";
	case alg_t::ES256:
		return "ES256";
	case alg_t::ES384:
		return "ES384";
	case alg_t::ES512:
		return "ES512";
	case alg_t::PS256:
		return "PS256";
	case alg_t::PS384:
		return "PS384";
	case alg_t::PS512:
		return "PS512";
#if defined(JWTPP_SUPPORTED_EDDSA)
	case alg_t::EdDSA:
		return "EdDSA";
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	default:
		return nullptr;
	}
}

alg_t crypto::str2alg(const std::string &a) {
	if (a == "none") {
		return alg_t::NONE;
	} else if (a == "HS256") {
		return alg_t::HS256;
	} else if (a == "HS384") {
		return alg_t::HS384;
	} else if (a == "HS512") {
		return alg_t::HS512;
	} else if (a == "RS256") {
		return alg_t::RS256;
	} else if (a == "RS384") {
		return alg_t::RS384;
	} else if (a == "RS512") {
		return alg_t::RS512;
	} else if (a == "ES256") {
		return alg_t::ES256;
	} else if (a == "ES384") {
		return alg_t::ES384;
	} else if (a == "ES512") {
		return alg_t::ES512;
	} else if (a == "PS256") {
		return alg_t::PS256;
	} else if (a == "PS384") {
		return alg_t::PS384;
	} else if (a == "PS512") {
		return alg_t::PS512;
	} else if (a == "EdDSA") {
#if defined(JWTPP_SUPPORTED_EDDSA)
		return alg_t::EdDSA;
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	} else {
		return alg_t::UNKNOWN;
	}
}

int crypto::hash2nid(digest::type type) {
	int ret = NID_sha256;

	switch (type) {
	case digest::type::SHA256:
		ret = NID_sha256;
		break;
	case digest::type::SHA384:
		ret = NID_sha384;
		break;
	case digest::type::SHA512:
		ret = NID_sha512;
		break;
	}

	return ret;
}

} // namespace jwtpp
