//
// Created by Artur Troian on 1/20/17.
//
#pragma once

namespace jwt {

enum class alg {
	NONE = 0,
	HS256,
	HS384,
	HS512,
	RS256,
	RS384,
	RS512,
	ES256,
	ES384,
	ES512,
	UNKNOWN
};

} // namespace jwt
