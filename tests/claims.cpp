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

	EXPECT_EQ("troian", cl->get().iss());
}
