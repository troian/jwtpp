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

TEST(JosePP, create_close_pss_crypto) {
	jwtpp::sp_rsa_key key;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(1024));

	EXPECT_NO_THROW(std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS384));
	EXPECT_THROW(std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS512), std::exception);

	EXPECT_THROW(std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::HS256), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::ES384), std::exception);
}

TEST(JosePP, sign_verify_pss256) {
	jwtpp::claims cl;

	jwtpp::sp_rsa_key key;
	jwtpp::sp_rsa_key pubkey;
	jwtpp::sp_crypto r256;
	jwtpp::sp_crypto r256_pub;
	jwtpp::sp_crypto r384;
	jwtpp::sp_crypto r384_pub;
	jwtpp::sp_crypto r512;
	jwtpp::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(1024));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r384 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS384));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS384));
	EXPECT_THROW(r512 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS512), std::exception);
	EXPECT_THROW(r512_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS512), std::exception);

	std::string bearer = jwtpp::jws::sign_bearer(cl, r256);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r256));
	EXPECT_TRUE(jws->verify(r256_pub));

	auto vf = [](jwtpp::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r256_pub, vf));
	EXPECT_THROW(jws->verify(r384_pub, vf), std::exception);
	EXPECT_THROW(jws->verify(r512_pub, vf), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_pss384) {
	jwtpp::claims cl;

	jwtpp::sp_rsa_key key;
	jwtpp::sp_rsa_key pubkey;
	jwtpp::sp_crypto r256;
	jwtpp::sp_crypto r256_pub;
	jwtpp::sp_crypto r384;
	jwtpp::sp_crypto r384_pub;
	jwtpp::sp_crypto r512;
	jwtpp::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(1024));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r384 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS384));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS384));
	EXPECT_THROW(r512 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS512), std::exception);
	EXPECT_THROW(r512_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS512), std::exception);

	std::string bearer = jwtpp::jws::sign_bearer(cl, r384);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r384_pub));

	auto vf = [](jwtpp::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r384_pub, vf));
	EXPECT_THROW(jws->verify(r256_pub, vf), std::exception);
	EXPECT_THROW(jws->verify(r512_pub, vf), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_pss512) {
	jwtpp::claims cl;

	jwtpp::sp_rsa_key key;
	jwtpp::sp_rsa_key pubkey;
	jwtpp::sp_crypto r256;
	jwtpp::sp_crypto r256_pub;
	jwtpp::sp_crypto r384;
	jwtpp::sp_crypto r384_pub;
	jwtpp::sp_crypto r512;
	jwtpp::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(2048));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS256));
	EXPECT_NO_THROW(r384 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS384));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS384));
	EXPECT_NO_THROW(r512 = std::make_shared<jwtpp::pss>(key, jwtpp::alg_t::PS512));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jwtpp::pss>(pubkey, jwtpp::alg_t::PS512));

	std::string bearer = jwtpp::jws::sign_bearer(cl, r512);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r512_pub));

	auto vf = [](jwtpp::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r512_pub, vf));
	EXPECT_THROW(jws->verify(r384_pub, vf), std::exception);
	EXPECT_THROW(jws->verify(r256_pub, vf), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}
