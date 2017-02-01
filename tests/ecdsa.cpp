//
// Created by Artur Troian on 1/20/17.
//

#include <gtest/gtest.h>

#include <josepp/claims.hpp>
#include <josepp/crypto.hpp>
#include <josepp/jws.hpp>

#include <openssl/err.h>

TEST(JosePP, sign_ecdsa256)
{
	jose::claims cl;

	jose::sp_ecdsa_key key;
	jose::sp_ecdsa_key pubkey;

	EXPECT_NO_THROW(key = jose::ecdsa::gen(NID_secp256k1));
	EXPECT_NO_THROW(pubkey = jose::sp_ecdsa_key(EC_KEY_new(), ::EC_KEY_free));

	const EC_GROUP *group = EC_KEY_get0_group(key.get());
	const EC_POINT *p = EC_KEY_get0_public_key(key.get());

	EXPECT_EQ(EC_KEY_set_group(pubkey.get(), group), 1);
	EXPECT_TRUE(p != NULL);
	EXPECT_EQ(EC_KEY_set_public_key(pubkey.get(), p), 1);

	jose::sp_crypto e256;
	jose::sp_crypto e384;
	jose::sp_crypto e512;
	jose::sp_crypto e256_pub;
	jose::sp_crypto e384_pub;
	jose::sp_crypto e512_pub;

	EXPECT_NO_THROW(e256 = std::make_shared<jose::ecdsa>(jose::alg::ES256, key));
	EXPECT_NO_THROW(e384 = std::make_shared<jose::ecdsa>(jose::alg::ES256, key));
	EXPECT_NO_THROW(e512 = std::make_shared<jose::ecdsa>(jose::alg::ES256, key));
	EXPECT_NO_THROW(e256_pub = std::make_shared<jose::ecdsa>(jose::alg::ES256, pubkey));
	EXPECT_NO_THROW(e384_pub = std::make_shared<jose::ecdsa>(jose::alg::ES256, pubkey));
	EXPECT_NO_THROW(e512_pub = std::make_shared<jose::ecdsa>(jose::alg::ES256, pubkey));

	std::string bearer = jose::jws::sign_bearer(cl, e256);

	EXPECT_TRUE(!bearer.empty());

	jose::sp_jws jws;

	EXPECT_NO_THROW(jws = jose::jws::parse(bearer));

	EXPECT_TRUE(jws->verify(e256_pub));

	auto vf = [](jose::sp_claims cl) {
		return !cl->check().iss("troian");
	};

	EXPECT_TRUE(jws->verify(e256_pub, std::bind<bool>(vf, std::placeholders::_1)));

	bearer = "ghdfgddf";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer ";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);

	bearer = "Bearer bla.bla.bla";
	EXPECT_THROW(jws = jose::jws::parse(bearer), std::exception);
}
