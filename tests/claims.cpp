//
// Created by Artur Troian on 2/1/17.
//

#include <gtest/gtest.h>

#include <josepp/claims.hpp>

TEST(JosePP, create_close_claims)
{
	EXPECT_NO_THROW(jose::claims cl);
	EXPECT_THROW(jose::claims cl(""), std::exception);
	EXPECT_THROW(jose::claims cl("", true), std::exception);
	EXPECT_THROW(jose::claims cl("jkhfkjsgdfg"), std::exception);

	jose::sp_claims cl;

	EXPECT_NO_THROW(cl = std::make_shared<jose::claims>());

	EXPECT_NO_THROW(cl->set().iss("troian"));
	EXPECT_NO_THROW(cl->set().iss("troian"));
	EXPECT_FALSE(cl->has().aud());

	EXPECT_TRUE("troian" == cl->get().iss());
}
