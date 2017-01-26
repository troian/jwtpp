//
// Created by Artur Troian on 1/20/17.
//

#include <jwtpp/claims.hpp>
#include <jwtpp/b64.hpp>
#include <jwtpp/tools.hpp>

namespace jwt {

void claims::set::any(const std::string &key, const std::string &value)
{
	if (key.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	claims_->operator[](key) = value;
}

claims::claims() :
	  claims_()
	, set_(&claims_)
	, get_(&claims_)
	, has_(&claims_)
	, del_(&claims_)
	, check_(&claims_)
{}

claims::claims(const std::string &d, bool b64) :
	claims()
{
	Json::Reader reader;

	if (b64) {
		std::string decoded = b64::decode_uri(d);

		if (!reader.parse(decoded, claims_)) {
			throw std::runtime_error("Invalid JSON input");
		}
	} else {
		if (!reader.parse(d, claims_)) {
			throw std::runtime_error("Invalid JSON input");
		}
	}
}

std::string claims::b64()
{
	return marshal_b64(claims_);
}

}
