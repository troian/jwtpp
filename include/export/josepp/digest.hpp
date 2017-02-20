//
// Created by Artur Troian on 2/1/17.
//
#pragma once

#include <cstring>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace jose {

/**
 * \brief
 */
class digest final {
public:
	enum class type {
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
