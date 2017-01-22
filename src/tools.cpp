/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Artur Troian
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <tools/tools.hpp>
#include <jwtpp/b64.hpp>

#include <json/writer.h>
#include <json/reader.h>

namespace jwt {

std::string marshal(const Json::Value &json)
{
	Json::FastWriter fastWriter;
	std::string s = fastWriter.write(json);
	return std::move(s);
}

std::string marshal_b64(const Json::Value &json)
{
	std::string s = marshal(json);
	std::string out;
	b64::encode(out, s);
	return out;
}

Json::Value unmarshal_b64(const std::string &b64)
{
	std::string decoded;
	decoded = b64::decode<std::string>(b64);

	Json::Value j;
	Json::Reader reader;
	if (!reader.parse(decoded, j)) {
		throw std::runtime_error("Invalid JSON input");
	}

	return j;
}

} // namespace tools
