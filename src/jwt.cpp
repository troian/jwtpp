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

jwt::jwt(jwt_alg_t alg, const uint8_t *key, size_t len) :
	  m_alg(alg)
	, m_key_len(len)
{
	m_key = new uint8_t[len];
	std::memcpy(m_key, key, len);
}

jwt::~jwt()
{
	scrub_key();
}

void jwt::scrub_key()
{
	if (m_key) {
		/* Overwrite it so it's gone from memory. */
		std::memset(m_key, 0, m_key_len);

		delete[] m_key;
	}

	m_key_len = 0;
	m_alg = JWT_ALG_NONE;
}

int jwt::sign(std::string &signature, const std::string &data)
{
	if (data.empty()) {
		return EINVAL;
	}

	signature.clear();
	signature.reserve(m_key_len);

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
	HMAC(alg, m_key, m_key_len, (const uint8_t *)data.c_str(), data.size(), nullptr, &res_len);

	uint8_t *res = new uint8_t[res_len];

	HMAC(alg, m_key, m_key_len, (const uint8_t *)data.c_str(), data.size(), res, &res_len);

	base64uri_encode(res, res_len);

	signature = tools::base64::encode(res, res_len);
	delete[] res;
	return 0;
}

std::string jwt::encode()
{
	Json::Value head;
	head["typ"] = "JWT";
	head["alg"] = alg2str(m_alg);

	std::string token;

	// Encode header into Base64
	std::string jhead = tools::serialize_json(head);
	token = tools::base64::encode(jhead);
	token += ".";

	// Encode parameters into Base64
	jhead.clear();
	jhead = tools::serialize_json(m_grants);
	token += tools::base64::encode(jhead);

	base64uri_encode(token);

	// Make signature
	std::string signature;
	sign(signature, token);

	token += ".";
	token += signature;
	return token;
}

void jwt::add_grant(const std::string &grant, const std::string &value)
{
	if (grant.empty() || value.empty())
		throw std::invalid_argument("Invalid params");

	if (m_grants.isMember(grant)) {
		throw std::runtime_error("Grant already exists");
	} else {
		m_grants[grant] = value;
	}
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
