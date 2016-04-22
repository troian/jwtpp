//
// Created by Artur Troian on 4/20/16.
//

#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <cstdint>
#include <errno.h>
#include <memory>

#include <json/json.h>

#include <tools/tools.hpp>

/**
 * \brief
 */
typedef enum jwt_alg {
	JWT_ALG_NONE = 0,
	JWT_ALG_HS256,
	JWT_ALG_HS384,
	JWT_ALG_HS512,
	JWT_ALG_UKNOWN
} jwt_alg_t;

/**
 * \brief
 */
class jwt {
public:
	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 * \param[in]
	 */
	explicit jwt(jwt_alg_t alg, const uint8_t *key, size_t len);
	~jwt();

	/**
	 * \brief
	 *
	 * \param[in]  key:
	 * \param[in]  value:
	 *
	 * \return None
	 */
	void add_grant(const std::string &key, const std::string &value);

	/**
	 * \brief
	 *
	 * \return
	 */
	std::string encode();

private:
	/*
	 * \brief  Cleanup key
	 *
	 * \return None
	 */
	void scrub_key();

	/**
	 * \brief   Sign data with key
	 *
	 * \param[out]  signature:
	 * \param[in]   data: data to be signed
	 *
	 * \return
	 */
	int sign(std::string &signature, const std::string &data);

private:
	/**
	 * \brief
	 *
	 * \param[in]
	 * \param[in]
	 *
	 * \return None
	 */
	static void base64uri_encode(uint8_t *buf, size_t len);

	/**
	 * \brief
	 *
	 * \param[in]  str:
	 *
	 * \return None
	 */
	static void base64uri_encode(std::string &str);

	/**
	 * \brief  Calculate length of key for given algorithm
	 *
	 * \param[in]  alg: value of type jwt_alg_t
	 *
	 * \retval  0 or positiv value: size of key
	 * \retval  -1: Unknown algorithm
	 */
	static int alg_key_len(jwt_alg_t alg);

	/**
	 * \brief  Convert algorithm represented as string into enum
	 *
	 * \param[in]  alg: Algorithm name as null-terminated string
	 *
	 * \retval     value of type jwt_alg_t
	 */
	static jwt_alg_t str2alg(const char *alg);

	/**
	 * brief  Convert algorithm value to it's string representation
	 *
	 * \param[in]  alg: value of type jwt_alg_t
	 *
	 * \retval     Null-terminated string representation or nullptr if value unknown
	 */
	static const char *alg2str(jwt_alg_t alg);

private:
	size_t        m_key_len;
	uint8_t      *m_key;
	jwt_alg_t     m_alg;
	Json::Value   m_grants;
};
