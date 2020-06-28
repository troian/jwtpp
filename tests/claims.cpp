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

TEST(jwtpp, create_close_claims)
{
	EXPECT_NO_THROW(jwtpp::claims cl);
	EXPECT_THROW(jwtpp::claims cl(""), std::exception);
	EXPECT_THROW(jwtpp::claims cl("", true), std::exception);
	EXPECT_THROW(jwtpp::claims cl("jkhfkjsgdfg"), std::exception);

	jwtpp::sp_claims cl;

	EXPECT_NO_THROW(cl = std::make_shared<jwtpp::claims>());

	EXPECT_THROW(cl->set().any("", "val"), std::exception);
	EXPECT_THROW(cl->set().any("key", ""), std::exception);

	EXPECT_NO_THROW(cl->set().iss("troian"));
	EXPECT_NO_THROW(cl->set().iss("troian"));

	EXPECT_FALSE(cl->has().aud());

	EXPECT_EQ("troian", cl->get().iss());
}

TEST(jwtpp, set_other_types_claims)
{
	jwtpp::claims cl;
	const Json::Int ts = 1593345759;
	cl.set().any("iat", ts);
	EXPECT_TRUE(cl.has().any("iat"));
	EXPECT_TRUE(cl.get().anyInt("iat") == ts);
	
	const Json::UInt uintval = 0x1d;
	cl.set().any("uintval", uintval);
	EXPECT_TRUE(cl.has().any("uintval"));
	EXPECT_TRUE(cl.get().anyUInt("uintval") == uintval);
	
	const Json::Int64 int64val = 0x1122334455667788;
	cl.set().any("int64val", int64val);
	EXPECT_TRUE(cl.has().any("int64val"));
	EXPECT_TRUE(cl.get().anyInt64("int64val") == int64val);
	
	const Json::UInt64 unsig64int = 0x8877665544332211;
	cl.set().any("unsig64int", unsig64int);
	EXPECT_TRUE(cl.has().any("unsig64int"));
	EXPECT_TRUE(cl.get().anyUInt64("unsig64int") == unsig64int);
	
	const double realval = 0.01;
	cl.set().any("realval", realval);
	EXPECT_TRUE(cl.has().any("realval"));
	EXPECT_TRUE(cl.get().anyDouble("realval"));
}

TEST(jwtpp, set__claim)
{
	jwtpp::claims cl;
	const Json::Int ts = 1593345759;
	cl.set().any("iat", ts);
	EXPECT_TRUE(cl.has().any("iat"));
	EXPECT_TRUE(cl.get().anyInt("iat") == ts);
}
