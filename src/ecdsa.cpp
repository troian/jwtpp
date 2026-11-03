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

#include <openssl/err.h>

#include <jwtpp/jwtpp.hh>

namespace jwtpp {

ecdsa::ecdsa(sp_ecdsa_key key, alg_t a)
	: crypto(a)
	, _e(key)
{
	if (a != alg_t::ES256 && a != alg_t::ES384 && a != alg_t::ES512) {
		throw std::invalid_argument("Invalid algorithm");
	}
}

std::string ecdsa::sign(const std::string &data) {
	if (data.empty()) {
		throw std::invalid_argument("data is empty");
	}

	auto sig = std::shared_ptr<uint8_t>(new uint8_t[ECDSA_size(_e.get())], std::default_delete<uint8_t[]>());

	digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

	uint32_t sig_len;

	if (ECDSA_sign(0, d.data(), static_cast<int>(d.size()), sig.get(), &sig_len, _e.get()) != 1) {
		throw std::runtime_error("Couldn't sign ECDSA");
	}

	return b64::encode_uri(sig.get(), sig_len);
}

bool ecdsa::verify(const std::string &data, const std::string &sig) {
    digest d(_hash_type, reinterpret_cast<const uint8_t *>(data.data()), data.length());

    auto raw = b64::decode_uri(sig.data(), sig.length());

    const EC_GROUP* group = EC_KEY_get0_group(_e.get());
    if (!group) {
        return false;
    }

    size_t half = (EC_GROUP_get_degree(group) + 7) / 8;

    if (raw.size() != 2 * half) {
        return false;
    }

    const unsigned char* p = reinterpret_cast<const unsigned char*>(raw.data());

    BIGNUM* r = BN_bin2bn(p, half, nullptr);
    BIGNUM* s = BN_bin2bn(p + half, half, nullptr);
    if (!r || !s) {
        BN_free(r);
        BN_free(s);
        return false;
    }

    ECDSA_SIG* sig_der = ECDSA_SIG_new();
    if (!sig_der) {
        BN_free(r);
        BN_free(s);
        return false;
    }

    if (ECDSA_SIG_set0(sig_der, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig_der);
        return false;
    }

    int ret = ECDSA_do_verify(
        d.data(),
        static_cast<int>(d.size()),
        sig_der,
        _e.get()
    );

    ECDSA_SIG_free(sig_der);
    return ret == 1;
}

sp_ecdsa_key ecdsa::gen(int nid) {
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

	if (EC_POINT_mul(group.get(), point.get(), priv, nullptr, nullptr, nullptr) != 1) {
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

} // namespace jwtpp
