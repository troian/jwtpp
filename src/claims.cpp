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

#include <sstream>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

void claims::set::any(const std::string &key, const std::string &value) {
	if (key.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	_claims->operator[](key) = value;
}

claims::claims()
	: _claims()
	, _set(&_claims)
	, _get(&_claims)
	, _has(&_claims)
	, _del(&_claims)
	, _check(&_claims)
{}

claims::claims(const std::string &d, bool b64) :
#if defined(_MSC_VER) && (_MSC_VER < 1700)
	  _claims()
	, _set(&_claims)
	, _get(&_claims)
	, _has(&_claims)
	, _del(&_claims)
	, _check(&_claims)
#else
	claims()
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)
{
	if (b64) {
		std::string decoded = b64::decode_uri(d);

		std::stringstream(decoded) >> _claims;
	} else {
		std::stringstream(d) >> _claims;
	}
}

std::string claims::b64() {
	return marshal_b64(_claims);
}

} // namespace jwtpp
