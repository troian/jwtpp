//
// Created by Artur Troian on 2/1/17.
//

#include <gtest/gtest.h>

#include <josepp/claims.hpp>
#include <josepp/crypto.hpp>
#include <josepp/jws.hpp>

TEST(JosePP, create_close_rsa_crypto)
{
	jose::sp_rsa_key key;

	EXPECT_NO_THROW(key = jose::rsa::gen(1024));

	EXPECT_NO_THROW(std::make_shared<jose::rsa>(jose::alg::RS256, key));
	EXPECT_NO_THROW(std::make_shared<jose::rsa>(jose::alg::RS384, key));
	EXPECT_NO_THROW(std::make_shared<jose::rsa>(jose::alg::RS512, key));

	EXPECT_THROW(std::make_shared<jose::rsa>(jose::alg::HS256, key), std::exception);
	EXPECT_THROW(std::make_shared<jose::rsa>(jose::alg::ES384, key), std::exception);
}

TEST(JosePP, sign_rsa256)
{
	jose::claims cl;

	jose::sp_rsa_key key;
	jose::sp_rsa_key pubkey;
	jose::sp_crypto r256;
	jose::sp_crypto r256_pub;
	jose::sp_crypto r384;
	jose::sp_crypto r384_pub;
	jose::sp_crypto r512;
	jose::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jose::rsa::gen(1024));
	EXPECT_NO_THROW(pubkey = jose::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jose::rsa>(jose::alg::RS256, key));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jose::rsa>(jose::alg::RS256, pubkey));
	EXPECT_NO_THROW(r384 = std::make_shared<jose::rsa>(jose::alg::RS384, key));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jose::rsa>(jose::alg::RS384, pubkey));
	EXPECT_NO_THROW(r512 = std::make_shared<jose::rsa>(jose::alg::RS512, key));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jose::rsa>(jose::alg::RS512, pubkey));

	std::string bearer = jose::jws::sign_bearer(cl, r256);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r256_pub));

	auto vf = [](jose::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r256_pub, std::bind<bool>(vf, std::placeholders::_1)));
	EXPECT_THROW(jws->verify(r384_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);
	EXPECT_THROW(jws->verify(r512_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_rsa384)
{
	jose::claims cl;

	jose::sp_rsa_key key;
	jose::sp_rsa_key pubkey;
	jose::sp_crypto r256;
	jose::sp_crypto r256_pub;
	jose::sp_crypto r384;
	jose::sp_crypto r384_pub;
	jose::sp_crypto r512;
	jose::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jose::rsa::gen(1024));
	EXPECT_NO_THROW(pubkey = jose::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jose::rsa>(jose::alg::RS256, key));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jose::rsa>(jose::alg::RS256, pubkey));
	EXPECT_NO_THROW(r384 = std::make_shared<jose::rsa>(jose::alg::RS384, key));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jose::rsa>(jose::alg::RS384, pubkey));
	EXPECT_NO_THROW(r512 = std::make_shared<jose::rsa>(jose::alg::RS512, key));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jose::rsa>(jose::alg::RS512, pubkey));

	std::string bearer = jose::jws::sign_bearer(cl, r384);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r384_pub));

	auto vf = [](jose::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r384_pub, std::bind<bool>(vf, std::placeholders::_1)));
	EXPECT_THROW(jws->verify(r256_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);
	EXPECT_THROW(jws->verify(r512_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}

TEST(JosePP, sign_rsa512)
{
	jose::claims cl;

	jose::sp_rsa_key key;
	jose::sp_rsa_key pubkey;
	jose::sp_crypto r256;
	jose::sp_crypto r256_pub;
	jose::sp_crypto r384;
	jose::sp_crypto r384_pub;
	jose::sp_crypto r512;
	jose::sp_crypto r512_pub;

	EXPECT_NO_THROW(key = jose::rsa::gen(1024));
	EXPECT_NO_THROW(pubkey = jose::sp_rsa_key(RSAPublicKey_dup(key.get()), ::RSA_free));
	EXPECT_NO_THROW(r256 = std::make_shared<jose::rsa>(jose::alg::RS256, key));
	EXPECT_NO_THROW(r256_pub = std::make_shared<jose::rsa>(jose::alg::RS256, pubkey));
	EXPECT_NO_THROW(r384 = std::make_shared<jose::rsa>(jose::alg::RS384, key));
	EXPECT_NO_THROW(r384_pub = std::make_shared<jose::rsa>(jose::alg::RS384, pubkey));
	EXPECT_NO_THROW(r512 = std::make_shared<jose::rsa>(jose::alg::RS512, key));
	EXPECT_NO_THROW(r512_pub = std::make_shared<jose::rsa>(jose::alg::RS512, pubkey));

	std::string bearer = jose::jws::sign_bearer(cl, r512);

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(r512_pub));

	auto vf = [](jose::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(r512_pub, std::bind<bool>(vf, std::placeholders::_1)));
	EXPECT_THROW(jws->verify(r384_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);
	EXPECT_THROW(jws->verify(r256_pub, std::bind<bool>(vf, std::placeholders::_1)), std::exception);

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}
