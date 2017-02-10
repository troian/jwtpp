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

#include <josepp/types.hpp>
#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>

namespace jose {

crypto::crypto(jose::alg alg) :
	alg_(alg)
{
	if (alg == jose::alg::HS256 || alg == jose::alg::RS256 || alg == jose::alg::ES256) {
		hash_type_ = digest::type::SHA256;
	} else if (alg == jose::alg::HS384 || alg == jose::alg::RS384 || alg == jose::alg::ES384) {
		hash_type_ = digest::type::SHA384;
	} else if (alg == jose::alg::HS512 || alg == jose::alg::RS512 || alg == jose::alg::ES512) {
		hash_type_ = digest::type::SHA512;
	}
}

crypto::~crypto()
{

}

const char *crypto::alg2str(jose::alg alg)
{
	switch (alg) {
	case jose::alg::NONE:
		return "none";
	case jose::alg::HS256:
		return "HS256";
	case jose::alg::HS384:
		return "HS384";
	case jose::alg::HS512:
		return "HS512";
	case jose::alg::RS256:
		return "RS256";
	case jose::alg::RS384:
		return "RS384";
	case jose::alg::RS512:
		return "RS512";
	default:
		return nullptr;
	}
}

jose::alg crypto::str2alg(const std::string &a)
{
	if (a == "none") {
		return jose::alg::NONE;
	} else if (a == "HS256") {
		return jose::alg::HS256;
	} else if (a == "HS384") {
		return jose::alg::HS384;
	} else if (a == "HS512") {
		return jose::alg::HS512;
	} else if (a == "RS256") {
		return jose::alg::RS256;
	} else if (a == "RS384") {
		return jose::alg::RS384;
	} else if (a == "RS512") {
		return jose::alg::RS512;
	} else if (a == "ES256") {
		return jose::alg::ES256;
	} else if (a == "ES384") {
		return jose::alg::ES384;
	} else if (a == "ES512") {
		return jose::alg::ES512;
	} else {
		return jose::alg::UNKNOWN;
	}
}

int crypto::hash2nid(digest::type type)
{
	int ret;

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

} // namespace jose
