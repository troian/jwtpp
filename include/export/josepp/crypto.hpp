// The MIT License (MIT)
//
// Copyright (c) 2016 Artur Troian
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

#pragma once

#include <json/json.h>

#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#include <string>
#include <memory>
#include <sstream>
#include <functional>

#include <josepp/types.hpp>
#include <josepp/digest.hpp>
#include <josepp/sstring.hh>

namespace jose {

#if defined(_MSC_VER) && (_MSC_VER < 1700)
    typedef std::shared_ptr<class crypto>   sp_crypto;
    typedef std::shared_ptr<class hmac>     sp_hmac;
    typedef std::shared_ptr<class rsa>      sp_rsa;
    typedef std::shared_ptr<class ecdsa>    sp_ecdsa;
    typedef std::shared_ptr<RSA>            sp_rsa_key;
    typedef std::shared_ptr<EC_KEY>         sp_ecdsa_key;
#else
    using sp_crypto    = typename std::shared_ptr<class crypto>;
    using sp_hmac      = typename std::shared_ptr<class hmac>;
    using sp_rsa       = typename std::shared_ptr<class rsa>;
    using sp_ecdsa     = typename std::shared_ptr<class ecdsa>;
    using sp_rsa_key   = typename std::shared_ptr<RSA>;
    using sp_ecdsa_key = typename std::shared_ptr<EC_KEY>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

class crypto {
public:
	using password_cb = std::function<void(secure_string &pass, int rwflag)>;

protected:
	struct on_password_wrap {
		explicit on_password_wrap(password_cb cb)
			: cb(cb)
			, required(false)
		{}

		password_cb cb;
		bool        required;
	};

public:
	/**
	 * \brief
	 *
	 * \param alg
	 */
	explicit crypto(jose::alg alg = jose::alg::NONE);

	virtual ~crypto() = 0;

public:
	/**
	 * \brief
	 *
	 * \return
	 */
	jose::alg alg() { return _alg; }
	jose::alg alg() const { return _alg; }

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
	static const char *alg2str(jose::alg alg);

	static jose::alg str2alg(const std::string &a);


protected:
	static int hash2nid(digest::type type);

protected:
	jose::alg      _alg;
	Json::Value    _hdr;
	digest::type   _hash_type;
};

class hmac : public crypto {
public:
	explicit hmac(jose::alg alg, const secure_string &secret);

	virtual ~hmac() = default;

public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
public:
	template <typename... _Args>
	static sp_hmac make_shared(_Args&&... __args) {
		return std::make_shared<class hmac>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

private:
	secure_string _secret;
};

class rsa : public crypto {
public:
	explicit rsa(jose::alg alg, sp_rsa_key key);

	virtual ~rsa();

public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

public:
#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
	template <typename... _Args>
	static sp_rsa make_shared(_Args&&... __args) {
		return std::make_shared<class rsa>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

	static sp_rsa_key gen(int size);

	static sp_rsa_key load_from_file(const std::string &path, password_cb on_password = nullptr);

	static sp_rsa_key load_from_string(const std::string &str) {
		auto key = std::shared_ptr<RSA>(RSA_new(), ::RSA_free);

		return key;
	}

private:
	static int password_loader(char *buf, int size, int rwflag, void *u);

private:
	sp_rsa_key   _r;
	unsigned int _key_size;
};

class ecdsa : public crypto {
public:
	explicit ecdsa(jose::alg alg, sp_ecdsa_key key);

	virtual ~ecdsa() = default;

public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

public:

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
	template <typename... _Args>
	static sp_ecdsa make_shared(_Args&&... __args) {
		return std::make_shared<class ecdsa>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

	static sp_ecdsa_key gen(int nid);

private:
	sp_ecdsa_key _e;
};

class pss : public crypto {
public:
	explicit pss(jose::alg alg, sp_rsa_key key);

	~pss() override = default;

public:
	std::string sign(const std::string &data) override;

	bool verify(const std::string &data, const std::string &sig) override;

private:
	sp_rsa_key _r;
	size_t     _key_size;
};

} // namespace jose
