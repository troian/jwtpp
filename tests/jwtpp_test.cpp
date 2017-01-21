//
// Created by Artur Troian on 1/20/17.
//

#include <gtest/gtest.h>

#include <jwt/claims.hpp>
#include <jwt/crypto.hpp>
#include <jwt/jws.hpp>

TEST(JwtPP, create_close_hmac_crypto)
{
	EXPECT_NO_THROW(std::make_shared<jwt::hmac>(jwt::alg::HS256, "secret"));
	EXPECT_NO_THROW(std::make_shared<jwt::hmac>(jwt::alg::HS384, "secret"));
	EXPECT_NO_THROW(std::make_shared<jwt::hmac>(jwt::alg::HS512, "secret"));

	EXPECT_THROW(std::make_shared<jwt::hmac>(jwt::alg::HS256, ""), std::exception);
	EXPECT_THROW(std::make_shared<jwt::hmac>(jwt::alg::NONE, "secret"), std::exception);
	EXPECT_THROW(std::make_shared<jwt::hmac>(jwt::alg::UNKNOWN, "secret"), std::exception);
}

TEST(JwtPP, create_close_claims)
{
	EXPECT_NO_THROW(jwt::claims cl);
	EXPECT_THROW(jwt::claims cl(""), std::exception);
	EXPECT_THROW(jwt::claims cl("", true), std::exception);
	EXPECT_THROW(jwt::claims cl("jkhfkjsgdfg"), std::exception);

	jwt::sp_claims cl;

	EXPECT_NO_THROW(cl = std::make_shared<jwt::claims>());

	EXPECT_NO_THROW(cl->set().iss("troian"));
	EXPECT_NO_THROW(cl->set().iss("troian"));
	EXPECT_FALSE(cl->has().aud());

	EXPECT_TRUE("troian" == cl->get().iss());
}

TEST(JwtPP, sign_hmac256)
{
	jwt::claims cl;

	std::string bearer("Bearer ");

	jwt::sp_crypto h256 = std::make_shared<jwt::hmac>(jwt::alg::HS256, "secret");
	jwt::sp_crypto h384 = std::make_shared<jwt::hmac>(jwt::alg::HS384, "secret");
	jwt::sp_crypto h512 = std::make_shared<jwt::hmac>(jwt::alg::HS512, "secret");

	bearer += jwt::jws::sign(cl, h256);

	jwt::sp_jws jws;

	EXPECT_NO_THROW(jws = jwt::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(h256));

	auto vf = [](jwt::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(h256, std::bind<bool>(vf, std::placeholders::_1)));

	EXPECT_THROW(jws->verify(h384), std::exception);
	EXPECT_THROW(jws->verify(h512), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);
}

TEST(JwtPP, sign_rsa256)
{
	jwt::claims cl;

	std::string bearer("Bearer ");

	RSA *r = RSA_new();
	BIGNUM *bn = BN_new();

	BN_set_word(bn, RSA_F4);

	RSA_generate_key_ex(r, 2048, bn, NULL);

	jwt::sp_crypto r256 = std::make_shared<jwt::rsa>(jwt::alg::RS256, r);

	bearer += jwt::jws::sign(cl, r256);

	jwt::sp_jws jws;

	EXPECT_NO_THROW(jws = jwt::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r256));

	auto vf = [](jwt::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r256, std::bind<bool>(vf, std::placeholders::_1)));

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jwt::jws::parse(bearer), std::exception);

	BN_free(bn);
	RSA_free(r);
}
