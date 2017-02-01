//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <memory>
#include <functional>
#include <vector>

#include <josepp/crypto.hpp>
#include <josepp/claims.hpp>
#include <josepp/header.hpp>

namespace jose {

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
	jws(jose::alg alg, const std::string &data, sp_claims cl, const std::string &sig);

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
	class claims &claims() {
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
	 * \brief Sign content and return signature
	 *
	 * \param[in]  data - data to be signed
	 * \param[in]  c - crypto to sign with
	 *
	 * \return signature
	 */
	static std::string sign(const std::string &data, sp_crypto c);

	static std::string sign_claims(class claims &cl, sp_crypto c);

	static std::string sign_bearer(class claims &cl, sp_crypto c);
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
	jose::alg    alg_;
	std::string data_;
	sp_claims   claims_;
	std::string sig_;
};

} // namespace jose
