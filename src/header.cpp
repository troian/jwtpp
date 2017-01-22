//
// Created by Artur Troian on 1/21/17.
//

#include <jwtpp/header.hpp>
#include <tools/tools.hpp>

namespace jwt {

hdr::hdr(jwt::alg alg)
{
	h_["typ"] = "JWT";
	h_["alg"]  = alg2str(alg);
}

hdr::hdr(const std::string &data)
{
	Json::Reader reader;

	if (!reader.parse(data, h_)) {
		throw std::runtime_error("Invalid JSON input");
	}
}

std::string hdr::b64()
{
	return marshal_b64(h_);
}

const char *hdr::alg2str(jwt::alg alg)
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

} // namespace jwt
