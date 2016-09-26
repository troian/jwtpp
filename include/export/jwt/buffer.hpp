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

/**
 * \brief
 */
using sp_key_buffer = typename std::shared_ptr<class key_buffer>;

/**
 * \brief
 */
using up_key_buffer = typename std::unique_ptr<class key_buffer>;

/**
 * \class
 *
 * \brief
 */
template<typename T>
class key_buffer final {
public:
	/**
	 * \brief
	 *
	 * \param[in] size
	 *
	 * \return
	 */
	explicit key_buffer(size_t size) :
		m_size(size) {

		if (size == 0)
			throw std::invalid_argument("size cannot be 0");

		try {
			m_data = new T[size];
		} catch (...) {
			throw;
		}
	}

	/**
	 * \brief
	 *
	 * \param[in] rhs
	 *
	 * \return
	 */
	key_buffer(key_buffer &rhs) {
		try {
			m_data = new T[rhs.m_size];
		} catch (...) {
			throw;
		}

		std::memcpy(m_data, rhs.m_data, sizeof(T) * m_size);
		m_size = rhs.m_size;
	}

	~key_buffer() {
		std::memset(m_data, 0, sizeof(T) * m_data);

		delete[] m_data;
	}

public:
	key_buffer &operator = (key_buffer &rhs) {
		if (this != &rhs) {
			try {
				m_data = new T[rhs.m_size];
			} catch (...) {
				throw;
			}

			std::memcpy(m_data, rhs.m_data, sizeof(T) * m_size);
			m_size = rhs.m_size;
		}

		return *this;
	}

	/**
	 * \brief
	 *
	 * \param[in]
	 *
	 * \return
	 */
	bool operator == (key_buffer &rhs) {
		if (m_size != rhs.m_size) {
			return false;
		}

		if (std::memcmp(m_data, rhs.m_data, sizeof(T) * m_size) == 0) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * \brief
	 *
	 * \param idx
	 *
	 * \return
	 */
	T &operator[] (size_t idx) {
		if (idx >= m_size) {
			throw std::out_of_range();
		}

		return m_data[idx];
	}

	T *data() {
		return m_data;
	}

	const T *data() const {
		return m_data;
	}

private:
	T     *m_data;
	size_t m_size;
};
