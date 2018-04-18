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

#include <gtest/gtest.h>

#include <algorithm>
#include <random>
#include <functional>

#include <josepp/b64.hpp>

TEST(JosePP, b64)
{
	std::vector<uint8_t> in;
	in.reserve(128);

	std::string b64;

	std::random_device rnd_device;
	// Specify the engine and distribution.
	std::mt19937 mersenne_engine(rnd_device());
	std::uniform_int_distribution<int> dist(0, 256);

	auto gen = std::bind(dist, mersenne_engine);

	std::generate(std::begin(in), std::end(in), gen);

	b64 = jose::b64::encode(in);

	std::vector<uint8_t> out;

	out = jose::b64::decode(b64.data(), b64.length());

	EXPECT_EQ(in.size(), out.size());
	EXPECT_EQ(in, out);

	b64.clear();
	out.clear();

	b64 = jose::b64::encode_uri(in);
	out = jose::b64::decode_uri(b64.data(), b64.length());

	EXPECT_EQ(in.size(), out.size());
	EXPECT_EQ(in, out);
}
