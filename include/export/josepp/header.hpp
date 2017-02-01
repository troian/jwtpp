//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <josepp/types.hpp>
#include <string>
#include <json/json.h>

namespace jose {

class hdr final {
public:
	explicit hdr(jose::alg alg);

	explicit hdr(const std::string &data);

	std::string b64();

private:
	static const char *alg2str(jose::alg alg);
private:
	Json::Value h_;
};

} // namespace jose
