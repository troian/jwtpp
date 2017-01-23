//
// Created by Artur Troian on 1/21/17.
//

#include <jwtpp/jws.hpp>
#include <tools/tools.hpp>

namespace jwt {

static const std::string bearer_hdr("bearer ");

jws::jws(jwt::alg alg, const std::string &data, sp_claims cl, const std::string &sig) :
	  alg_(alg)
	, data_(data)
	, claims_(cl)
	, sig_(sig)
{

}

bool jws::verify(sp_crypto c, verify_cb v)
{
	if (c->alg() != alg_) {
		throw std::runtime_error("Invalid Crypto Alg");
	}

	if (!c->verify(data_, sig_)) {
		return false;
	}

	if (v) {
		return v(claims_);
	}

	return true;
}

sp_jws jws::parse(const std::string &full_bearer)
{
	if (full_bearer.empty() || full_bearer.length() < bearer_hdr.length()) {
		throw std::invalid_argument("Bearer is invalid or empty");
	}

	for(size_t i = 0; i < bearer_hdr.length(); i++) {

		if (bearer_hdr[i] != tolower(full_bearer[i])) {
			throw std::invalid_argument("Bearer header is invalid");
		}
	}

	std::string bearer = full_bearer.substr(bearer_hdr.length());

	std::vector<std::string> tokens;
	tokens = tokenize(bearer, '.');

	if (tokens.size() != 3) {
		throw std::runtime_error("Bearer is invalid");
	}

	Json::Value hdr;

	try {
	 	hdr = unmarshal_b64(tokens[0]);
	} catch (...) {
		throw;
	}

	if (!hdr.isMember("typ") || !hdr.isMember("alg")) {
		throw std::runtime_error("Invalid JWT header");
	}

	if (hdr["typ"].asString() != "JWT") {
		throw std::runtime_error("Is not JWT");
	}

	jwt::alg alg = crypto::str2alg(hdr["alg"].asString());
	if (alg >= jwt::alg::UNKNOWN) {
		throw std::runtime_error("Invalid alg");
	}

	sp_claims cl;

	try {
		cl = std::make_shared<class claims>(tokens[1], true);
	} catch (...) {
		throw;
	}

	std::string d = tokens[0];
	d += ".";
	d += tokens[1];

	jws *j = new jws(alg, d, cl, tokens[2]);

	if (!j) {
		throw std::runtime_error("Couldn't create jws object");
	}

	return sp_jws(j);
}

std::string jws::sign(class claims &cl, sp_crypto c) {
	std::string bearer;

	hdr h(c->alg());
	bearer = h.b64();
	bearer += ".";
	bearer += cl.b64();

	std::string sig;
	sig = c->sign(bearer);
	bearer += ".";
	bearer += sig;

	return bearer;
}

std::string jws::bearer(class claims &cl, sp_crypto c)
{
	std::string bearer("Bearer ");
	bearer += sign(cl, c);
	return bearer;
}
std::vector<std::string> jws::tokenize(const std::string &text, char sep)
{
	std::vector<std::string> tokens;
	std::size_t start = 0;
	std::size_t end = 0;

	while ((end = text.find(sep, start)) != std::string::npos) {
		tokens.push_back(text.substr(start, end - start));
		start = end + 1;
	}

	tokens.push_back(text.substr(start));

	return std::move(tokens);
}

} // namespace jwt
