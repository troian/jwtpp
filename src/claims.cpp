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

#include <josepp/claims.hpp>
#include <josepp/b64.hpp>
#include <josepp/tools.hpp>

namespace jose {

void claims::set::any(const std::string &key, const std::string &value)
{
	if (key.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	claims_->operator[](key) = value;
}

claims::claims() :
	  claims_()
	, set_(&claims_)
	, get_(&claims_)
	, has_(&claims_)
	, del_(&claims_)
	, check_(&claims_)
{}

claims::claims(const std::string &d, bool b64) :
	claims()
{
	Json::Reader reader;

	if (b64) {
		std::string decoded = b64::decode_uri(d);

		if (!reader.parse(decoded, claims_)) {
			throw std::runtime_error("Invalid JSON input");
		}
	} else {
		if (!reader.parse(d, claims_)) {
			throw std::runtime_error("Invalid JSON input");
		}
	}
}

std::string claims::b64()
{
	return marshal_b64(claims_);
}

} // namespace jose
