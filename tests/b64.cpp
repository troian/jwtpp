//
// Created by Artur Troian on 2/1/17.
//

#include <algorithm>
#include <random>

#include <gtest/gtest.h>

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
