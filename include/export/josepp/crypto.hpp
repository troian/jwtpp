//
// Created by Artur Troian on 1/20/17.
//
#pragma once

#include <string>
#include <memory>
#include <sstream>

#include <josepp/types.hpp>

#include <json/json.h>

#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

namespace jwt {

using sp_crypto = typename std::shared_ptr<class crypto>;
using sp_hmac   = typename std::shared_ptr<class hmac>;
using sp_rsa    = typename std::shared_ptr<class rsa>;
using sp_ecdsa  = typename std::shared_ptr<class ecdsa>;

using sp_rsa_key = typename std::shared_ptr<RSA>;

using sp_ecdsa_key = typename std::shared_ptr<EC_KEY>;

class crypto {
protected:
	enum class hash_type {
		SHA256,
		SHA384,
		SHA512
	};

	class sha2_digest {
	public:
		sha2_digest(hash_type type, const uint8_t *in_data, size_t in_size) {
			switch(type) {
			case hash_type::SHA256:
				size_ = SHA256_DIGEST_LENGTH;
				break;
			case hash_type::SHA384:
				size_ = SHA384_DIGEST_LENGTH;
				break;
			case hash_type::SHA512:
				size_ = SHA512_DIGEST_LENGTH;
				break;
			}

			data_ = std::shared_ptr<uint8_t>(new uint8_t[size_], std::default_delete<uint8_t[]>());

			switch (type) {
			case hash_type::SHA256: {
				SHA256_CTX sha_ctx;
				if (SHA256_Init(&sha_ctx) != 1) {
					throw std::runtime_error("Couldn't init SHA256");
				}

				if (SHA256_Update(&sha_ctx, in_data, in_size) != 1) {
					throw std::runtime_error("Couldn't calculate hash");
				}

				if (SHA256_Final(data_.get(), &sha_ctx) != 1) {
					throw std::runtime_error("Couldn't finalize SHA");
				}
				break;
			}
			case hash_type::SHA384: {
				SHA512_CTX sha_ctx;

				if (SHA384_Init(&sha_ctx) != 1) {
					throw std::runtime_error("Couldn't init SHA384");
				}

				if (SHA384_Update(&sha_ctx, in_data, in_size) != 1) {
					throw std::runtime_error("Couldn't calculate hash");
				}

				if (SHA384_Final(data_.get(), &sha_ctx) != 1) {
					throw std::runtime_error("Couldn't finalize SHA");
				}
				break;
			}
			case hash_type::SHA512: {
				SHA512_CTX sha_ctx;

				if (SHA512_Init(&sha_ctx) != 1) {
					throw std::runtime_error("Couldn't init SHA512");
				}

				if (SHA512_Update(&sha_ctx, in_data, in_size) != 1) {
					throw std::runtime_error("Couldn't calculate hash");
				}

				if (SHA512_Final(data_.get(), &sha_ctx) != 1) {
					throw std::runtime_error("Couldn't finalize SHA");
				}
				break;
			}
			}
		}

		size_t size() const {
			return size_;
		}

		uint8_t *data() {
			return data_.get();
		}

	private:
		size_t size_;
		int    type_;
		std::shared_ptr<uint8_t> data_;
	};

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

class ecdsa : public crypto {
public:
	explicit ecdsa(jwt::alg alg, EC_KEY *e);

	virtual ~ecdsa();
public:
	virtual std::string sign(const std::string &data);
	virtual bool verify(const std::string &data, const std::string &sig);

public:
	template <typename... _Args>
	static sp_ecdsa make_shared(_Args&&... __args) {
		return std::make_shared<class ecdsa>(__args...);
	}

	static sp_ecdsa_key gen(int nid) {
		sp_ecdsa_key key = std::shared_ptr<EC_KEY>(EC_KEY_new(), ::EC_KEY_free);
		std::shared_ptr<EC_GROUP> group = std::shared_ptr<EC_GROUP>(EC_GROUP_new_by_curve_name(nid), ::EC_GROUP_free);

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

		if (EC_KEY_check_key(key.get()) != 1) {
			throw std::runtime_error("EC check failed");
		}

		return key;
	}
private:
	EC_KEY *e_;
};
} // namespace jwt
