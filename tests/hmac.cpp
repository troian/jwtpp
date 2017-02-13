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

#include <josepp/claims.hpp>
#include <josepp/crypto.hpp>
#include <josepp/jws.hpp>

TEST(JosePP, create_close_hmac_crypto)
{
	EXPECT_NO_THROW(std::make_shared<jose::hmac>(jose::alg::HS256, "secret"));
	EXPECT_NO_THROW(std::make_shared<jose::hmac>(jose::alg::HS384, "secret"));
	EXPECT_NO_THROW(std::make_shared<jose::hmac>(jose::alg::HS512, "secret"));

	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::HS256, ""), std::exception);
	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::HS384, ""), std::exception);
	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::HS512, ""), std::exception);
	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::NONE, "secret"), std::exception);
	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::UNKNOWN, "secret"), std::exception);

	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::ES512, ""), std::exception);
	EXPECT_THROW(std::make_shared<jose::hmac>(jose::alg::RS256, ""), std::exception);
}

TEST(JosePP, sign_verify_hmac256)
{
	jose::claims cl;

	cl.set().iss("troian");

	jose::sp_crypto h256 = std::make_shared<jose::hmac>(jose::alg::HS256, "secret");
	jose::sp_crypto h384 = std::make_shared<jose::hmac>(jose::alg::HS384, "secret");
	jose::sp_crypto h512 = std::make_shared<jose::hmac>(jose::alg::HS512, "secret");

	std::string bearer = jose::jws::sign_bearer(cl, h256);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h256));

	auto vf = [](jose::sp_claims cl) {
		return cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(h256, std::bind<bool>(vf, std::placeholders::_1)));

	EXPECT_THROW(jws->verify(h384), std::exception);
	EXPECT_THROW(jws->verify(h512), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_hmac384)
{
	jose::claims cl;

	cl.set().iss("troian");

	jose::sp_crypto h256 = std::make_shared<jose::hmac>(jose::alg::HS256, "secret");
	jose::sp_crypto h384 = std::make_shared<jose::hmac>(jose::alg::HS384, "secret");
	jose::sp_crypto h512 = std::make_shared<jose::hmac>(jose::alg::HS512, "secret");

	std::string bearer = jose::jws::sign_bearer(cl, h384);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h384));

	auto vf = [](jose::sp_claims cl) {
		return cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(h384, std::bind<bool>(vf, std::placeholders::_1)));

	EXPECT_THROW(jws->verify(h256), std::exception);
	EXPECT_THROW(jws->verify(h512), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_verify_hmac512)
{
	jose::claims cl;

	cl.set().iss("troian");

	jose::sp_crypto h256 = std::make_shared<jose::hmac>(jose::alg::HS256, "secret");
	jose::sp_crypto h384 = std::make_shared<jose::hmac>(jose::alg::HS384, "secret");
	jose::sp_crypto h512 = std::make_shared<jose::hmac>(jose::alg::HS512, "secret");

	std::string bearer = jose::jws::sign_bearer(cl, h512);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h512));

	auto vf = [](jose::sp_claims cl) {
		return cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(h512, std::bind<bool>(vf, std::placeholders::_1)));

	EXPECT_THROW(jws->verify(h384), std::exception);
	EXPECT_THROW(jws->verify(h256), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}

