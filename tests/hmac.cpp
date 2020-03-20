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

TEST(JosePP, create_close_hmac_crypto)
{
	EXPECT_NO_THROW(std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS256));
	EXPECT_NO_THROW(std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS384));
	EXPECT_NO_THROW(std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS512));

	EXPECT_THROW(std::make_shared<jwtpp::hmac>("", jwtpp::alg_t::HS256), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::hmac>("", jwtpp::alg_t::HS384), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::hmac>("", jwtpp::alg_t::HS512), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::NONE), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::UNKNOWN), std::exception);

	EXPECT_THROW(std::make_shared<jwtpp::hmac>("", jwtpp::alg_t::ES512), std::exception);
	EXPECT_THROW(std::make_shared<jwtpp::hmac>("", jwtpp::alg_t::RS256), std::exception);
}

TEST(JosePP, sign_verify_hmac256)
{
	jwtpp::claims cl;

	cl.set().iss("troian");

	jwtpp::sp_crypto h256 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS256);
	jwtpp::sp_crypto h384 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS384);
	jwtpp::sp_crypto h512 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS512);

	std::string bearer = jwtpp::jws::sign_bearer(cl, h256);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h256));

	auto vf = [](jwtpp::sp_claims cl) {
		return cl->check().iss("troian");
	};

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    EXPECT_TRUE(jws->verify(h256, vf));
#else
	EXPECT_TRUE(jws->verify(h256, std::bind<bool>(vf, std::placeholders::_1)));
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

	EXPECT_THROW(jws->verify(h384), std::exception);
	EXPECT_THROW(jws->verify(h512), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_hmac384)
{
	jwtpp::claims cl;

	cl.set().iss("troian");

	jwtpp::sp_crypto h256 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS256);
	jwtpp::sp_crypto h384 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS384);
	jwtpp::sp_crypto h512 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS512);

	std::string bearer = jwtpp::jws::sign_bearer(cl, h384);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h384));

	auto vf = [](jwtpp::sp_claims cl) {
		return cl->check().iss("troian");
	};

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    EXPECT_TRUE(jws->verify(h384, vf));
#else
	EXPECT_TRUE(jws->verify(h384, std::bind<bool>(vf, std::placeholders::_1)));
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

	EXPECT_THROW(jws->verify(h256), std::exception);
	EXPECT_THROW(jws->verify(h512), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_hmac512)
{
	jwtpp::claims cl;

	cl.set().iss("troian");

	jwtpp::sp_crypto h256 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS256);
	jwtpp::sp_crypto h384 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS384);
	jwtpp::sp_crypto h512 = std::make_shared<jwtpp::hmac>("secret", jwtpp::alg_t::HS512);

	std::string bearer = jwtpp::jws::sign_bearer(cl, h512);

	jwtpp::sp_jws jws;

	EXPECT_NO_THROW(jws = jwtpp::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h512));

	auto vf = [](jwtpp::sp_claims cl) {
		return cl->check().iss("troian");
	};

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    EXPECT_TRUE(jws->verify(h512, vf));
#else
    EXPECT_TRUE(jws->verify(h512, std::bind<bool>(vf, std::placeholders::_1)));
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

	EXPECT_THROW(jws->verify(h384), std::exception);
	EXPECT_THROW(jws->verify(h256), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwtpp::jws::parse(bearer), std::exception);
}

