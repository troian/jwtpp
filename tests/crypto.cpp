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

#include <gtest/gtest.h>

#include <jwtpp/jwtpp.hh>

TEST(jwtpp, crypto_str2alg) {
	EXPECT_EQ(jwtpp::alg_t::NONE,  jwtpp::crypto::str2alg("none"));
	EXPECT_EQ(jwtpp::alg_t::HS256, jwtpp::crypto::str2alg("HS256"));
	EXPECT_EQ(jwtpp::alg_t::HS384, jwtpp::crypto::str2alg("HS384"));
	EXPECT_EQ(jwtpp::alg_t::HS512, jwtpp::crypto::str2alg("HS512"));
	EXPECT_EQ(jwtpp::alg_t::RS256, jwtpp::crypto::str2alg("RS256"));
	EXPECT_EQ(jwtpp::alg_t::RS384, jwtpp::crypto::str2alg("RS384"));
	EXPECT_EQ(jwtpp::alg_t::RS512, jwtpp::crypto::str2alg("RS512"));
	EXPECT_EQ(jwtpp::alg_t::ES256, jwtpp::crypto::str2alg("ES256"));
	EXPECT_EQ(jwtpp::alg_t::ES384, jwtpp::crypto::str2alg("ES384"));
	EXPECT_EQ(jwtpp::alg_t::ES512, jwtpp::crypto::str2alg("ES512"));
	EXPECT_EQ(jwtpp::alg_t::PS256, jwtpp::crypto::str2alg("PS256"));
	EXPECT_EQ(jwtpp::alg_t::PS384, jwtpp::crypto::str2alg("PS384"));
	EXPECT_EQ(jwtpp::alg_t::PS512, jwtpp::crypto::str2alg("PS512"));
#if defined(JWTPP_SUPPORTED_EDDSA)
	EXPECT_EQ(jwtpp::alg_t::EdDSA, jwtpp::crypto::str2alg("EdDSA"));
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	EXPECT_EQ(jwtpp::alg_t::UNKNOWN, jwtpp::crypto::str2alg("bsd"));
}

TEST(jwtpp, crypto_alg2str) {
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::NONE)),  std::string("none"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::HS256)), std::string("HS256"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::HS384)), std::string("HS384"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::HS512)), std::string("HS512"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::RS256)), std::string("RS256"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::RS384)), std::string("RS384"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::RS512)), std::string("RS512"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::ES256)), std::string("ES256"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::ES384)), std::string("ES384"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::ES512)), std::string("ES512"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::PS256)), std::string("PS256"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::PS384)), std::string("PS384"));
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::PS512)), std::string("PS512"));
#if defined(JWTPP_SUPPORTED_EDDSA)
	EXPECT_EQ(std::string(jwtpp::crypto::alg2str(jwtpp::alg_t::EdDSA)), std::string("EdDSA"));
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	EXPECT_EQ(jwtpp::crypto::alg2str(jwtpp::alg_t::UNKNOWN), nullptr);
}
