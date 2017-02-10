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

#include <josepp/tools.hpp>
#include <josepp/b64.hpp>

//#include <json/writer.h>
//#include <json/reader.h>

namespace jose {

std::string marshal(const Json::Value &json)
{
	Json::StreamWriterBuilder builder;
	builder["commentStyle"] = "None";
	builder["indentation"] = ""; // Write in one line
	std::string out = Json::writeString(builder, json);
	return std::move(out);
}

std::string marshal_b64(const Json::Value &json)
{
	std::string s = marshal(json);
	return std::move(b64::encode_uri(s));
}

Json::Value unmarshal(const std::string &in)
{
	Json::Value j;
	Json::Reader reader;
	if (!reader.parse(in, j)) {
		throw std::runtime_error("Invalid JSON input");
	}

	return j;
}

Json::Value unmarshal_b64(const std::string &b64)
{
	std::string decoded;
	decoded = b64::decode(b64);
	return unmarshal(decoded);
}

} // namespace jose
