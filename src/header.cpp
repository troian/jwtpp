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

#include <josepp/header.hpp>
#include <josepp/tools.hpp>

namespace jose {

hdr::hdr(jose::alg alg) :
	h_()
{
	h_["typ"] = "JWT";
	h_["alg"]  = alg2str(alg);
}

hdr::hdr(const std::string &data) :
	h_()
{
	Json::Reader reader;

	if (!reader.parse(data, h_)) {
		throw std::runtime_error("Invalid JSON input");
	}
}

std::string hdr::b64()
{
	return marshal_b64(h_);
}

const char *hdr::alg2str(jose::alg alg)
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
	case jose::alg::ES256:
		return "ES256";
	case jose::alg::ES384:
		return "ES384";
	case jose::alg::ES512:
		return "ES512";
	default:
		return nullptr;
	}
}

} // namespace jose
