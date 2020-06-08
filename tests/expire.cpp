  
// The MIT License (MIT)
//
// Copyright (c) 2020 ihmc3jn09hk
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

TEST(jwtpp, check_expire) {
	auto future_t = std::chrono::system_clock::now() + std::chrono::seconds{30};
	auto future = std::chrono::system_clock::to_time_t(future_t);

	jwtpp::claims cl;

	cl->set().exp(std::to_string(future));
  
	jwtpp::sp_rsa_key key;
	jwtpp::sp_rsa_key pubkey;

	jwtpp::sp_crypto r512;
	jwtpp::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jwtpp::rsa::gen(4096));
	EXPECT_NO_THROW(pubkey = jwtpp::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));

	EXPECT_NO_THROW(r512 = std::make_shared<jwtpp::rsa>(key, jwtpp::alg_t::RS512));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jwtpp::rsa>(pubkey, jwtpp::alg_t::RS512));

	std::string bearer = jwtpp::jws::sign_bearer(cl, r512);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));
  
	auto now_t = std::chrono::system_clock::now();
	auto now =std::chrono::system_clock::to_time_t(now_t);

	auto vf = [&now](jwtpp::sp_claims cl) {
		time_t &&future_s = std::stoll(cl->get().exp());
		return 0 < difftime(future_s, now);
	};

	EXPECT_TRUE(jws->verify(r512_pub, vf));

	auto vf = [&now](jwtpp::sp_claims cl) {
		time_t &&future_s = std::stoll(cl->get().exp());
		return 0 > difftime(now, future_s);
	};

	EXPECT_TRUE(jws->verify(r512_pub, vf));
}
