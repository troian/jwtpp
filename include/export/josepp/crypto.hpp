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
#include <cstdio>
#include <iostream>

#include <josepp/types.hpp>
#include <josepp/digest.hpp>
#include <josepp/string.hh>

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
		explicit on_password_wrap(password_cb cb) :
			  cb(cb)
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
	jose::alg alg() { return alg_; }
	jose::alg alg() const { return alg_; }

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
	jose::alg      alg_;
	Json::Value    hdr_;
	digest::type   hash_type_;
};

class hmac : public crypto {
public:
	explicit hmac(jose::alg alg, const std::string &secret);

	virtual ~hmac();
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
	std::string secret_;
};

class rsa : public crypto {
public:
	explicit rsa(jose::alg alg, sp_rsa_key key);

	virtual ~rsa() = default;

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

	static sp_rsa_key gen(int size) {
		// keys less than 1024 bits are insecure
		if ((size % 1024) != 0) {
			throw std::invalid_argument("Invalid keys size");
		}

		sp_rsa_key key = std::shared_ptr<RSA>(RSA_new(), ::RSA_free);
		BIGNUM *bn = BN_new();
		BN_set_word(bn, RSA_F4);
		RSA_generate_key_ex(key.get(), size, bn, NULL);

		return key;
	}

	static sp_rsa_key load_from_file(const std::string &path, password_cb on_password = nullptr) {
		RSA *r;

		auto pass_loader = [](char *buf, int size, int rwflag, void *u) -> int {
			auto wrap = reinterpret_cast<on_password_wrap *>(u);

			if (wrap->cb == nullptr) {
				wrap->required = true;
				return 0;
			}

			secure_string pass;
			int pass_size = 0;
			try {
				wrap->cb(pass, rwflag);
				pass_size = pass.copy(buf, secure_string::size_type(size), 0);
			} catch (...) {
				pass_size = 0;
			}

			std::cout << "pass: " << pass;
			return pass_size;
		};

		auto f = std::fopen(path.c_str(), "r");
		if (!f) {
			throw std::runtime_error("cannot open file");
		}

		on_password_wrap wrap(on_password);

		r = PEM_read_RSAPrivateKey(f, nullptr, pass_loader, &wrap);
		if (wrap.required) {
			throw std::runtime_error("password required");
		} else if (r == nullptr) {
			throw std::runtime_error("read rsa key");
		}

		return std::shared_ptr<RSA>(r, ::RSA_free);
	}

private:
	sp_rsa_key r_;
};

class ecdsa : public crypto {
public:
	explicit ecdsa(jose::alg alg, sp_ecdsa_key key);

	virtual ~ecdsa();
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

	static sp_ecdsa_key gen(int nid) {
		sp_ecdsa_key key = std::shared_ptr<EC_KEY>(EC_KEY_new(), ::EC_KEY_free);
		std::shared_ptr<EC_GROUP> group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(nid), ::EC_GROUP_free);
		std::shared_ptr<EC_POINT> point = std::shared_ptr<EC_POINT>(EC_POINT_new(group.get()), ::EC_POINT_free);

		if (EC_KEY_set_group(key.get(), group.get()) != 1) {
			throw std::runtime_error("Couldn't set EC KEY group");
		}

		int degree = EC_GROUP_get_degree(EC_KEY_get0_group(key.get()));
		if (degree < 160) {
			std::stringstream str;
			str << "Skip the curve [" << OBJ_nid2sn(nid) << "] (degree = " << degree << ")";
			throw std::runtime_error(str.str());
		}

		if (EC_KEY_generate_key(key.get()) != 1) {
			throw std::runtime_error("Couldn't generate EC KEY");
		}

		const BIGNUM *priv = EC_KEY_get0_private_key(key.get());

		if (EC_POINT_mul(group.get(), point.get(), priv, NULL, NULL, NULL) != 1) {
			throw std::runtime_error("Couldn't generate EC PUB KEY");
		}

		if (EC_KEY_set_public_key(key.get(), point.get()) != 1) {
			throw std::runtime_error("Couldn't set EC PUB KEY");
		}

		if (EC_KEY_check_key(key.get()) != 1) {
			throw std::runtime_error("EC check failed");
		}

		return key;
	}
private:
	sp_ecdsa_key e_;
};
} // namespace jose
