//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <string>
#include <memory>

#include <jwtpp/types.hpp>

#include <json/json.h>

#include <openssl/rsa.h>

namespace jwt {

using sp_crypto = typename std::shared_ptr<class crypto>;
using sp_hmac = typename std::shared_ptr<class hmac>;
using sp_rsa = typename std::shared_ptr<class rsa>;

using sp_rsa_key = typename std::shared_ptr<RSA>;

class crypto {
public:
	/**
	 * \brief
	 *
	 * \param alg
	 */
	explicit crypto(jwt::alg alg = jwt::alg::NONE);

	virtual ~crypto() = 0;

public:
	/**
	 * \brief
	 *
	 * \return
	 */
	jwt::alg alg() { return alg_; }
	jwt::alg alg() const { return alg_; }

	/**
	 * \brief
	 *
	 * \param data
	 *
	 * \return
	 */
	virtual std::string sign(const std::string &data) = 0;

	/**
	 * \brief
	 *
	 * \param data
	 * \param sig
	 *
	 * \return
	 */
	virtual bool verify(const std::string &data, const std::string &sig) = 0;

public:
	/**
	 * \brief
	 *
	 * \param alg
	 *
	 * \return
	 */
	static const char *alg2str(jwt::alg alg);

	static jwt::alg str2alg(const std::string &a);

protected:
	jwt::alg    alg_;
	Json::Value hdr_;
};

class hmac : public crypto {
public:
	explicit hmac(jwt::alg alg, const std::string &secret);

	virtual ~hmac();
public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

public:
	template <typename... _Args>
	static sp_hmac make_shared(_Args&&... __args) {
		return std::make_shared<class hmac>(__args...);
	}

private:
	std::string secret_;
};

class rsa : public crypto {
public:
	explicit rsa(jwt::alg alg, RSA *r);

	virtual ~rsa();
public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

public:
	template <typename... _Args>
	static sp_rsa make_shared(_Args&&... __args) {
		return std::make_shared<class rsa>(__args...);
	}

	static sp_rsa_key gen() {
		sp_rsa_key key = std::shared_ptr<RSA>(RSA_new(), ::RSA_free);
		return key;
	}
private:
	RSA *r_;
};

} // namespace jwt
