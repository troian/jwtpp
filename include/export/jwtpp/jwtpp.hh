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

#pragma once

#include <memory>
#include <functional>
#include <vector>
#include <string>
#include <sstream>

#include <json/json.h>

#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

#if __cplusplus >= 201703L
#   define __NODISCARD [[nodiscard]]
#else
#   define __NODISCARD
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#   define JWTPP_SUPPORTED_EDDSA
#endif

namespace jwtpp {

class claims;
class crypto;
class hmac;
class rsa;
class ecdsa;

#if defined(_MSC_VER) && (_MSC_VER < 1700)
enum alg_t {
#else
enum class alg_t {
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)
	NONE = 0,
	HS256,
	HS384,
	HS512,
	RS256,
	RS384,
	RS512,
	ES256,
	ES384,
	ES512,
	PS256,
	PS384,
	PS512,
#if defined(JWTPP_SUPPORTED_EDDSA)
	EdDSA,
#endif // defined(JWTPP_SUPPORTED_EDDSA)
	UNKNOWN
};

#if defined(_MSC_VER) && (_MSC_VER < 1700)
#   define final

	typedef std::shared_ptr<class claims>                    sp_claims;
	typedef std::unique_ptr<class claims>                    up_claims;
	typedef std::shared_ptr<class crypto>                    sp_crypto;
	typedef std::shared_ptr<class hmac>                      sp_hmac;
	typedef std::shared_ptr<class rsa>                       sp_rsa;
	typedef std::shared_ptr<class ecdsa>                     sp_ecdsa;
	typedef std::shared_ptr<RSA>                             sp_rsa_key;
	typedef std::shared_ptr<EC_KEY>                          sp_ecdsa_key;
	typedef std::shared_ptr<EVP_PKEY>                        sp_evp_key;

	typedef std::shared_ptr<EVP_MD_CTX>                      sp_evp_md_ctx;
	typedef std::shared_ptr<EVP_PKEY_CTX>                    sp_evp_pkey_ctx;

	typedef std::unique_ptr<std::FILE, int (*)(std::FILE *)> up_file;
#else
	using sp_claims       = typename std::shared_ptr<class claims>;
	using up_claims       = typename std::unique_ptr<class claims>;
	using sp_crypto       = typename std::shared_ptr<class crypto>;
	using sp_hmac         = typename std::shared_ptr<class hmac>;
	using sp_rsa          = typename std::shared_ptr<class rsa>;
	using sp_ecdsa        = typename std::shared_ptr<class ecdsa>;
	using sp_rsa_key      = typename std::shared_ptr<RSA>;
	using sp_ecdsa_key    = typename std::shared_ptr<EC_KEY>;
	using sp_evp_key      = typename std::shared_ptr<EVP_PKEY>;

	using sp_evp_md_ctx   = typename std::shared_ptr<EVP_MD_CTX>;
	using sp_evp_pkey_ctx = typename std::shared_ptr<EVP_PKEY_CTX>;

	using up_file         = typename std::unique_ptr<std::FILE, int (*)(std::FILE *)>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

template <class T>
class secure_allocator : public std::allocator<T> {
public:
	template <class U>
	struct rebind {
		typedef secure_allocator<U> other;
	};

	secure_allocator() noexcept = default;

	secure_allocator(const secure_allocator &) noexcept
		: std::allocator<T>()
	{}

	template <class U>
	explicit secure_allocator(const secure_allocator<U> &) noexcept {}

	void deallocate(T *p, std::size_t n) noexcept {
		OPENSSL_cleanse(p, n);
		std::allocator<T>::deallocate(p, n);
	}
};

using secure_string = std::basic_string<char, std::char_traits<char>, secure_allocator<char>>;

class b64 final {
private:
	static const std::string base64_chars;

	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

	static void uri_enc(char *buf, size_t len);

	static void uri_dec(char *buf, size_t len);

public:
	/**
	 * \brief
	 *
	 * \param[out]  b64: output data in base64
	 * \param[in]
	 *
	 * \return  None
	 */
	static std::string encode(const uint8_t *stream, size_t in_len);
	static std::string encode(const std::vector<uint8_t> &stream);
	static std::string encode(const std::vector<uint8_t> *stream);
	static std::string encode(const std::string &stream);

	static std::string encode_uri(const uint8_t * stream, size_t in_len);
	static std::string encode_uri(const std::string &stream);
	static std::string encode_uri(const std::vector<uint8_t> &stream);
	static std::string encode_uri(const std::vector<uint8_t> * stream);

	static std::vector<uint8_t> decode(const char *in, size_t in_size);
	static std::vector<uint8_t> decode_uri(const char *in, size_t in_size);
	static std::string decode(const std::string &in);
	static std::string decode_uri(const std::string &in);
};

/**
 * \brief
 */
class digest final {
public:
#if defined(_MSC_VER) && (_MSC_VER < 1700)
	enum type {
#else
	enum class type {
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)
		SHA256,
		SHA384,
		SHA512
	};

public:
	digest(digest::type type, const uint8_t *in_data, size_t in_size);
	~digest();

	__NODISCARD
	size_t size() const;

	uint8_t *data();

	__NODISCARD
	std::string to_string() const;

public:
	static const EVP_MD *md(digest::type t) {
		switch (t) {
		default:
			[[fallthrough]];
		case type::SHA256:
			return EVP_sha256();
		case type::SHA384:
			return EVP_sha384();
		case type::SHA512:
			return EVP_sha512();
		}
	}

private:
	size_t                   _size;
	std::shared_ptr<uint8_t> _data;
};

/**
* \brief
*
* TODO https://github.com/troian/jwtpp/issues/38
*/
class claims final {
private:
	class has {
	public:
		explicit has(Json::Value *c) : _claims(c) {}
	public:
		bool any(const std::string &key) { return _claims->isMember(key); }
		bool iss() { return any("iss"); }
		bool sub() { return any("sub"); }
		bool aud() { return any("aud"); }
		bool exp() { return any("exp"); }
		bool nbf() { return any("nbf"); }
		bool iat() { return any("iat"); }
		bool jti() { return any("jti"); }
	private:
		Json::Value *_claims;
	};

	class check {
	public:
		explicit check(Json::Value *c) : _claims(c) {}
	public:
		bool any(const std::string &key, const std::string &value) {
			std::string s = _claims->operator[](key).asString();
			return s == value;
		}
		
		bool any(const std::string &key, Json::UInt value) { return _claims->operator[](key).asUInt() == value; }
		bool any(const std::string &key, Json::Int value) { return _claims->operator[](key).asInt() == value; }
		bool any(const std::string &key, Json::UInt64 value) { return _claims->operator[](key).asUInt64() == value; }
		bool any(const std::string &key, Json::Int64 value) { return _claims->operator[](key).asInt64() == value; }
		bool any(const std::string &key, double value) { return _claims->operator[](key).asDouble() == value; }
		
		bool iss(const std::string &value) { return any("iss", value); }
		bool sub(const std::string &value) { return any("sub", value); }
		bool aud(const std::string &value) { return any("aud", value); }
		bool exp(const std::string &value) { return any("exp", value); }
		bool nbf(const std::string &value) { return any("nbf", value); }
		bool iat(const std::string &value) { return any("iat", value); }
		bool jti(const std::string &value) { return any("jti", value); }
	private:
		Json::Value *_claims;
	};

	class del {
	public:
		explicit del(Json::Value *c) : _claims(c) {}
	public:
		void any(const std::string &key) { _claims->removeMember(key); }
		void iss() { any("iss"); }
		void sub() { any("sub"); }
		void aud() { any("aud"); }
		void exp() { any("exp"); }
		void nbf() { any("nbf"); }
		void iat() { any("nbf"); }
		void jti() { any("jti"); }
	private:
		Json::Value *_claims;
	};


	class get {
	public:
		explicit get(Json::Value *c) : _claims(c) {}
	public:
		std::string any(const std::string &key) {
			return _claims->operator[](key).asString();
		}
		
		Json::Int anyInt(const std::string &key) {
			return _claims->operator[](key).asInt();
		}
		
		Json::UInt anyUInt(const std::string &key) {
			return _claims->operator[](key).asUInt();
		}
		
		Json::Int64 anyInt64(const std::string &key) {
			return _claims->operator[](key).asInt64();
		}
		
		Json::UInt64 anyUInt64(const std::string &key) {
			return _claims->operator[](key).asUInt64();
		}
		
		bool anyBool(const std::string &key) {
			return _claims->operator[](key).asBool();
		}
		
		double anyDouble(const std::string &key) {
			return _claims->operator[](key).asDouble();
		}
		
		std::string iss() { return any("iss"); }
		std::string sub() { return any("sub"); }
		std::string aud() { return any("aud"); }
		std::string exp() { return any("exp"); }
		std::string nbf() { return any("nbf"); }
		std::string iat() { return any("iat"); }
		std::string jti() { return any("jti"); }
	private:
		Json::Value *_claims;
	};

	class set {
	public:
		explicit set(Json::Value *c) : _claims(c) {}
	public:
		void any(const std::string &key, Json::UInt value) { _claims->operator[](key) = value; }
		void any(const std::string &key, Json::Int value) { _claims->operator[](key) = value; }
		void any(const std::string &key, Json::UInt64 value) { _claims->operator[](key) = value; }
		void any(const std::string &key, Json::Int64 value) { _claims->operator[](key) = value; }
		void any(const std::string &key, double value) { _claims->operator[](key) = value; }
		void any(const std::string &key, const std::string &value);
		
		void iss(const std::string &value) { any("iss", value); }
		void sub(const std::string &value) { any("sub", value); }
		void aud(const std::string &value) { any("aud", value); }
		void exp(const std::string &value) { any("exp", value); }
		void nbf(const std::string &value) { any("nbf", value); }
		void iat(const std::string &value) { any("iat", value); }
		void jti(const std::string &value) { any("jti", value); }

	private:
		Json::Value *_claims;
	};
public:
	/**
	 * \brief
	 */
	claims();

	/**
	 * \brief
	 *
	 * \param d
	 */
	explicit claims(const std::string &d, bool b64 = false);

	/**
	 * \brief
	 *
	 * \param key
	 * \param value
	 *
	 * \return
	 */
	class claims::set &set() { return _set; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::has &has() { return _has; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::del &del() { return _del; }

	/**
	 * \brief
	 *
	 * \param key
	 *
	 * \return
	 */
	class claims::get &get() { return _get; }

	class claims::check &check() { return _check; }

	std::string b64();

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
public:
	template <typename... _Args>
	static sp_claims make_shared(_Args&&... __args) {
		return std::make_shared<class claims>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

private:
	Json::Value _claims;

	class set   _set;
	class get   _get;
	class has   _has;
	class del   _del;
	class check _check;
};

class hdr final {
public:
	explicit hdr(jwtpp::alg_t alg);

	explicit hdr(const std::string &data);

	std::string b64();

private:
	Json::Value _h;
};

/**
 * \brief
 */
#if defined(_MSC_VER) && (_MSC_VER < 1700)
	typedef std::shared_ptr<class jws> sp_jws;
#else
	using sp_jws = typename std::shared_ptr<class jws>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

class jws final {
public:
#if defined(_MSC_VER) && (_MSC_VER < 1700)
	typedef std::function<bool (sp_claims cl)> verify_cb;
#else
	using verify_cb = typename std::function<bool (sp_claims cl)>;
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

private:
	/**
	 * \brief
	 *
	 * \param alg
	 * \param data
	 * \param cl
	 * \param sig
	 */
	jws(alg_t a, const std::string &data, sp_claims cl, const std::string &sig);

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
		return *(_claims.get());
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
	alg_t        _alg;
	std::string  _data;
	sp_claims    _claims;
	std::string  _sig;
};

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
	explicit crypto(alg_t a = alg_t::NONE);

	virtual ~crypto() = 0;

public:
	/**
	 * \brief
	 *
	 * \return
	 */
	__NODISCARD
	alg_t alg() { return _alg; }

	__NODISCARD
	alg_t alg() const { return _alg; }

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
	static const char *alg2str(alg_t a);

	static alg_t str2alg(const std::string &a);


protected:
	static int hash2nid(digest::type type);

protected:
	alg_t          _alg;
	Json::Value    _hdr;
	digest::type   _hash_type;
};

class hmac : public crypto {
public:
	explicit hmac(const secure_string &secret, alg_t a = alg_t::HS256);

	~hmac() override = default;

public:
	std::string sign(const std::string &data) override;
	bool verify(const std::string &data, const std::string &sig) override;

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
	explicit rsa(sp_rsa_key key, alg_t a = alg_t::RS256);

	~rsa() override;

public:
	std::string sign(const std::string &data) override;
	bool verify(const std::string &data, const std::string &sig) override;

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
	explicit ecdsa(sp_ecdsa_key key, alg_t a = alg_t::ES256);

	~ecdsa() override = default;

public:
	std::string sign(const std::string &data) override;
	bool verify(const std::string &data, const std::string &sig) override;

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

#if defined(JWTPP_SUPPORTED_EDDSA)
class eddsa : public crypto {
public:
	explicit eddsa(sp_evp_key key, alg_t a = alg_t::EdDSA);

	~eddsa() override = default;

public:
	std::string sign(const std::string &data) override;
	bool verify(const std::string &data, const std::string &sig) override;

public:

#if !(defined(_MSC_VER) && (_MSC_VER < 1700))
	template <typename... _Args>
	static sp_ecdsa make_shared(_Args&&... __args) {
		return std::make_shared<class ecdsa>(__args...);
	}
#endif // !(defined(_MSC_VER) && (_MSC_VER < 1700))

	static sp_evp_key gen();
	static sp_evp_key get_pub(sp_evp_key priv);

private:
	sp_evp_key _e;
};
#endif // defined(JWTPP_SUPPORTED_EDDSA)

class pss : public crypto {
public:
	explicit pss(sp_rsa_key key, alg_t a = alg_t::PS256);

	~pss() override = default;

public:
	std::string sign(const std::string &data) override;
	bool verify(const std::string &data, const std::string &sig) override;

private:
	sp_rsa_key _r;
	size_t     _key_size;
};

std::string marshal(const Json::Value &json);

std::string marshal_b64(const Json::Value &json);

Json::Value unmarshal(const std::string &in);

Json::Value unmarshal_b64(const std::string &b);

#if defined(_MSC_VER) && (_MSC_VER < 1700)
#   undef final
#endif

} // namespace jwtpp
