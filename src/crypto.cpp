//
// Created by Artur Troian on 1/20/17.
//

#include <josepp/types.hpp>
#include <josepp/crypto.hpp>
#include <josepp/b64.hpp>

namespace jwt {

crypto::crypto(jwt::alg alg) :
	alg_(alg)
{
}

crypto::~crypto()
{

}

const char *crypto::alg2str(jwt::alg alg)
{
	switch (alg) {
	case jwt::alg::NONE:
		return "none";
	case jwt::alg::HS256:
		return "HS256";
	case jwt::alg::HS384:
		return "HS384";
	case jwt::alg::HS512:
		return "HS512";
	case jwt::alg::RS256:
		return "RS256";
	case jwt::alg::RS384:
		return "RS384";
	case jwt::alg::RS512:
		return "RS512";
	default:
		return nullptr;
	}
}

jwt::alg crypto::str2alg(const std::string &a)
{
	if (a == "none") {
		return jwt::alg::NONE;
	} else if (a == "HS256") {
		return jwt::alg::HS256;
	} else if (a == "HS384") {
		return jwt::alg::HS384;
	} else if (a == "HS512") {
		return jwt::alg::HS512;
	} else if (a == "RS256") {
		return jwt::alg::RS256;
	} else if (a == "RS384") {
		return jwt::alg::RS384;
	} else if (a == "RS512") {
		return jwt::alg::RS512;
	} else {
		return jwt::alg::UNKNOWN;
	}
}

} // namespace jwt
