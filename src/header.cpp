//
// Created by Artur Troian on 1/21/17.
//

#include <josepp/header.hpp>
#include <josepp/tools.hpp>

namespace jose {

hdr::hdr(jose::alg alg)
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

const char *hdr::alg2str(jose::alg alg)
{
	switch (alg) {
	case jose::alg::NONE:
		return "none";
	case jose::alg::HS256:
		return "HS256";
	case jose::alg::HS384:
		return "HS384";
	case jose::alg::HS512:
		return "HS512";
	case jose::alg::RS256:
		return "RS256";
	case jose::alg::RS384:
		return "RS384";
	case jose::alg::RS512:
		return "RS512";
	case jose::alg::ES256:
		return "ES256";
	case jose::alg::ES384:
		return "ES384";
	case jose::alg::ES512:
		return "ES512";
	default:
		return nullptr;
	}
}

} // namespace jose
