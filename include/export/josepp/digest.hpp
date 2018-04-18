//
// Created by Artur Troian on 2/1/17.
//
#pragma once

#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>

#if defined(_MSC_VER) && (_MSC_VER < 1700)
#define final
#endif // defined(_MSC_VER) && (_MSC_VER < 1700)

namespace jose {

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

	size_t size() const;

	uint8_t *data();

private:
	size_t                   size_;
	std::shared_ptr<uint8_t> data_;
};

} // namespace jose
