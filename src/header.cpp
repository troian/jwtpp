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

hdr::hdr(alg_t a)
	: _h()
{
	_h["typ"] = "JWT";
	_h["alg"]  = crypto::alg2str(a);
}

hdr::hdr(const std::string &data)
	: _h()
{
	std::stringstream(data) >> _h;

	if (!_h.isMember("typ") || !_h["typ"].isString()) {
		throw std::runtime_error("stream does not have valid \"typ\" field");
	}

	if (_h["typ"].asString() != "JWT") {
		throw std::runtime_error("invalid \"typ\" value");
	}

	if (!_h.isMember("alg") || !_h["alg"].isString()) {
		throw std::runtime_error("stream does not have valid \"alg\" field");
	}

	if (crypto::str2alg(_h["alg"].asString()) == alg_t::UNKNOWN) {
		throw std::runtime_error("invalid \"alg\" value");
	}
}

std::string hdr::b64() {
	return marshal_b64(_h);
}

} // namespace jwtpp
