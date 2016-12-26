/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Artur Troian
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

#include <memory>
#include <cstring>

/// \brief
using sp_key_buffer = typename std::shared_ptr<class key_buffer>;

/// \brief
using up_key_buffer = typename std::unique_ptr<class key_buffer>;

/// \tparam T
template<typename T>
class key_buffer final {
private:
	typedef T value_type;

public:
	/**
	 * \brief
	 *
	 * \param[in] size
	 */
	explicit key_buffer(size_t size) :
		size_(size)
	{

		if (size == 0)
			throw std::invalid_argument("size cannot be 0");

		try {
			data_ = new T[size];
		} catch (...) {
			throw;
		}
	}

	/**
	 *
	 * \param[in] rhs
	 */
	key_buffer(key_buffer &rhs) {
		try {
			data_ = new T[rhs.size_];
		} catch (...) {
			throw;
		}

		std::memcpy(data_, rhs.data_, sizeof(value_type) * size_);
		size_ = rhs.size_;
	}

	/**
	 * \brief
	 */
	~key_buffer() {
		std::memset(data_, 0, sizeof(value_type) * data_);

		delete[] data_;
	}

public:
	/**
	 * \brief
	 *
	 * \param[in] rhs
	 *
	 * \return
	 */
	key_buffer &operator = (key_buffer &rhs) {
		if (this != &rhs) {
			try {
				data_ = new T[rhs.size_];
			} catch (...) {
				throw;
			}

			std::memcpy(data_, rhs.data_, sizeof(T) * size_);
			size_ = rhs.size_;
		}

		return *this;
	}

	/**
	 * \brief
	 *
	 * \param[in] rhs
	 *
	 * \return
	 */
	bool operator == (key_buffer &rhs) {
		if (size_ != rhs.size_) {
			return false;
		}

		return std::memcmp(data_, rhs.data_, sizeof(T) * size_) == 0;
	}

	/**
	 * \brief
	 *
	 * \param[in]  idx
	 *
	 * \return
	 */
	T &operator[] (size_t idx) {
		if (idx >= size_) {
			std::string error("Index " + std::to_string(idx) + " is out ot of range");
			throw std::out_of_range(error);
		}

		return data_[idx];
	}

	/**
	 * \brief
	 *
	 * \return
	 */
	T *data() {
		return data_;
	}

	/**
	 * \brief
	 *
	 * \return
	 */
	const T *data() const {
		return data_;
	}

private:
	T     *data_;
	size_t size_;
};
