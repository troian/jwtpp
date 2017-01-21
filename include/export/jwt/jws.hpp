//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <memory>
#include <functional>

#include <jwt/crypto.hpp>
#include <jwt/claims.hpp>
#include <jwt/header.hpp>

namespace jwt {

/**
 * \brief
 */
using sp_jws = typename std::shared_ptr<class jws>;

class jws final {
public:
	using verify_cb = typename std::function<bool (sp_claims cl)>;

private:
	/**
	 * \brief
	 *
	 * \param alg
	 * \param data
	 * \param cl
	 * \param sig
	 */
	jws(jwt::alg alg, const std::string &data, sp_claims cl, const std::string &sig);

public:
	/**
	 * \brief
	 *
	 * \return
	 */
	bool is_jwt();

	/**
	 * \brief
	 *
	 * \param c
	 * \param v
	 * \return
	 */
	bool verify(sp_crypto c, verify_cb v = nullptr);

	/**
	 * \brief
	 *
	 * \return
	 */
	claims &claims() {
		return *(claims_.get());
	}

public:
	/**
	 * \brief
	 *
	 * \param b
	 *
	 * \return
	 */
	static sp_jws parse(const std::string &b);

	/**
	 * \brief
	 *
	 * \param cl
	 * \param c
	 *
	 * \return
	 */
	static std::string sign(class claims &cl, sp_crypto c);

private:
	/**
	 * \brief
	 *
	 * \param text
	 * \param sep
	 * \return
	 */
	static std::vector<std::string> tokenize(const std::string &text, char sep);

private:
	jwt::alg    alg_;
	std::string data_;
	sp_claims   claims_;
	std::string sig_;
};

} // namespace jwt
