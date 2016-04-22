/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Artur Troian
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <iostream>
#include <sstream>
#include <iomanip>

#include <jwt/jwt.hpp>
#include <tools/base64.hpp>

#include <openssl/hmac.h>

jwt::jwt(jwt_alg_t alg) :
	  m_alg(alg)
{

}

jwt::jwt(const std::string &token)
{
	try {
		parse(token);
	} catch (...) {
		throw;
	}
}

jwt::~jwt()
{
	cleanup();
}

int jwt::gen_signature(std::string &signature, const std::string &data, const uint8_t *key, size_t key_size)
{
	if (data.empty()) {
		return EINVAL;
	}

	signature.clear();

	uint32_t res_len;

	const EVP_MD *alg;

	switch (m_alg) {
	case JWT_ALG_NONE:
		return 0;
	case JWT_ALG_HS256:
		alg = EVP_sha256();
		break;
	case JWT_ALG_HS384:
		alg = EVP_sha384();
		break;
	case JWT_ALG_HS512:
		alg = EVP_sha512();
		break;
	default:
		// Should actualy never happen
		return EINVAL;
	}

	// First calculate len of the signature
	HMAC(alg, key, key_size, (const uint8_t *)data.c_str(), data.size(), nullptr, &res_len);

	uint8_t *res = new uint8_t[res_len];

	HMAC(alg, key, key_size, (const uint8_t *)data.c_str(), data.size(), res, &res_len);

	base64uri_encode(res, res_len);

	signature = tools::base64::encode(res, res_len);

	delete[] res;

	return 0;
}

std::string jwt::sign(const uint8_t *key, size_t key_size)
{
	m_header["typ"] = "JWT";
	m_header["alg"] = alg2str(m_alg);

	std::string token;

	// Encode header into Base64
	std::string jhead = tools::serialize_json(m_header);
	token = tools::base64::encode(jhead);
	token += ".";

	// Encode parameters into Base64
	jhead.clear();
	jhead = tools::serialize_json(m_payload);
	token += tools::base64::encode(jhead);

	base64uri_encode(token);

	// Make signature
	gen_signature(m_signature, token, key, key_size);

	token += ".";
	token += m_signature;
	return token;
}

bool jwt::verify(const uint8_t *key, size_t size)
{
	// Make signature
	std::string token = m_tokens[0] + "." + m_tokens[1];
	gen_signature(m_signature, token, key, size);

	if (m_signature.compare(m_tokens[2]) == 0) {
		return true;
	} else {
		return false;
	}
}

void jwt::add_grant(const std::string &grant, const std::string &value)
{
	if (grant.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	if (m_payload.isMember(grant)) {
		throw std::runtime_error("Grant already exists");
	} else {
		m_payload[grant] = value;
	}
}

bool jwt::grant_verify(const std::string &grant, const std::string &value)
{
	if (grant.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	if (!m_payload.isMember(grant)) {
		throw std::runtime_error("Grant not found");
	}

	std::string val = m_payload.get(grant, "").asString();
	if (val.compare(value) == 0) {
		return true;
	} else {
		return false;
	}
}

void jwt::cleanup()
{
	m_header.clear();
	m_payload.clear();
	m_signature.clear();
	m_tokens.clear();
}

void jwt::parse(const std::string &token)
{
	if (token.empty()) {
		throw std::runtime_error("Invalid argument");
	}

	// extracting the algorithm, payload, signature and data
	m_tokens = split(token, '.');

	std::string decoded_header  = tools::base64::decode<std::string>(m_tokens[0]);
	std::string decoded_payload = tools::base64::decode<std::string>(m_tokens[1]);

	if (m_tokens.size() != 3) {
		throw std::runtime_error("Invalid token string");
	}

	try {
		tools::str2json(decoded_header, m_header);
	} catch (const std::exception &e) {
		std::cout << e.what();
	}

	std::string ser = tools::serialize_json(m_header);

	std::string typ = m_header.get("typ", "Unknown").asString();

	if (typ.compare("Unknown") == 0) {
		throw std::runtime_error("Bad token type");
	}

	std::string alg = m_header.get("alg", "Unknown").asString();

	m_alg = str2alg(alg.c_str());
	if (m_alg == JWT_ALG_UKNOWN) {
		std::string error("Bad algorithm [");
		error += alg;
		error += "]";
		throw std::runtime_error(error);
	}

	try {
		tools::str2json(decoded_payload, m_payload);
	} catch (const std::exception &e) {
		std::cout << e.what();
	}
}

std::vector<std::string> jwt::split(const std::string &text, char sep)
{
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

void jwt::base64uri_encode(std::string &str)
{
	size_t t;

	for (size_t i = t = 0; i < str.size(); i++) {
		switch (str[i]) {
		case '+':
			str[t] = '-';
			break;
		case '/':
			str[t] = '_';
			break;
		case '=':
			continue;
		}

		t++;
	}

}

void jwt::base64uri_encode(uint8_t *buf, size_t len)
{
	int i, t;

	for (i = t = 0; i < len; i++) {
		switch (buf[i]) {
		case '+':
			buf[t] = '-';
			break;
		case '/':
			buf[t] = '_';
			break;
		case '=':
			continue;
		}

		t++;
	}

	//buf[t] = '\0';
}

const char *jwt::alg2str(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return "none";
	case JWT_ALG_HS256:
		return "HS256";
	case JWT_ALG_HS384:
		return "HS384";
	case JWT_ALG_HS512:
		return "HS512";
	default:
		return nullptr;
	}
}

jwt_alg_t jwt::str2alg(const char *alg)
{
	if (!strcasecmp(alg, "none"))
		return JWT_ALG_NONE;
	else if (!strcasecmp(alg, "HS256"))
		return JWT_ALG_HS256;
	else if (!strcasecmp(alg, "HS384"))
		return JWT_ALG_HS384;
	else if (!strcasecmp(alg, "HS512"))
		return JWT_ALG_HS512;
	else
		return JWT_ALG_UKNOWN;
}

int jwt::alg_key_len(jwt_alg_t alg)
{
	switch (alg) {
	case JWT_ALG_NONE:
		return 0;
	case JWT_ALG_HS256:
		return 32;
	case JWT_ALG_HS384:
		return 48;
	case JWT_ALG_HS512:
		return 64;
	default:
		return -1; // LCOV_EXCL_LINE
	}
}