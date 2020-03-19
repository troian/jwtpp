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

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

static const std::string bearer_hdr("bearer ");

jws::jws(alg_t a, const std::string &data, sp_claims cl, const std::string &sig)
	: _alg(a)
	, _data(data)
	, _claims(cl)
	, _sig(sig) {

}

bool jws::verify(sp_crypto c, verify_cb v) {
	if (!c) {
		throw std::runtime_error("uninitialized crypto");
	}

	if (c->alg() != _alg) {
		throw std::runtime_error("invalid crypto alg");
	}

	if (!c->verify(_data, _sig)) {
		return false;
	}

	if (v) {
		return v(_claims);
	}

	return true;
}

sp_jws jws::parse(const std::string &full_bearer) {
	if (full_bearer.empty() || full_bearer.length() < bearer_hdr.length()) {
		throw std::invalid_argument("Bearer is invalid or empty");
	}

	for (size_t i = 0; i < bearer_hdr.length(); i++) {

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

	alg_t a = crypto::str2alg(hdr["alg"].asString());
	if (a >= alg_t::UNKNOWN) {
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

	jws *j;

	try {
		j = new jws(a, d, cl, tokens[2]);
	} catch (...) {
		throw;
	}

	return sp_jws(j);
}

std::string jws::sign(const std::string &data, sp_crypto c) {
	return c->sign(data);
}

std::string jws::sign_claims(class claims &cl, sp_crypto c) {
	std::string out;

	hdr h(c->alg());
	out = h.b64();
	out += ".";
	out += cl.b64();

	std::string sig;
	sig = jws::sign(out, c);
	out += ".";
	out += sig;

	return out;
}

std::string jws::sign_bearer(class claims &cl, sp_crypto c) {
	std::string bearer("Bearer ");
	bearer += jws::sign_claims(cl, c);
	return bearer;
}

std::vector<std::string> jws::tokenize(const std::string &text, char sep) {
	std::vector<std::string> tokens;
	std::size_t start = 0;
	std::size_t end = 0;

	while ((end = text.find(sep, start)) != std::string::npos) {
		tokens.push_back(text.substr(start, end - start));
		start = end + 1;
	}

	tokens.push_back(text.substr(start));

	return tokens;
}

} // namespace jwtpp
