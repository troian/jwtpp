//
// Created by Artur Troian on 16.10.2019
//

#pragma once

#include <new>
#include <utility>
#include <cstdint>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace jwtpp {

template<typename T, typename ... Args>
T *instantiate(Args && ...args) noexcept {
	auto buf = new uint8_t[sizeof(T)];
	return new(buf) T(std::forward<T>(args)...);
}

class static_init {
public:
	static_init() noexcept {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		SSL_library_init();
#else
		OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, nullptr);
#endif

		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		ERR_load_crypto_strings();
	}

	void operator()() {}

	static static_init &inst() noexcept {
		static static_init __inst;
		return __inst;
	}
};

extern static_init &static_instance;

} // namespace jwtpp
