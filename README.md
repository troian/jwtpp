# josepp
JSON Object Signing and Encryption library for C++

[![Build Status](https://travis-ci.org/troian/josepp.svg?branch=master)](https://travis-ci.org/troian/josepp)

#### Dependencies:
  - [jsoncpp](https://github.com/open-source-parsers/jsoncpp)
  - OpenSSL

#### Supported features:
  - Sign
  - Verify

#### Supported algorithms
|Alg|Status|
|:---:|:------:|
| HS256 | **Supported** |
| HS384 | **Supported** |
| HS512 | **Supported** |
| RS256 | **Supported** |
| RS384 | **Supported** |
| RS512 | **Supported** |
| ES256 | Not Supported |
| ES384 | Not Supported |
| ES512 | Not Supported |

#### Claims
|Claim|Status|
|:---:|:----:|
|**_ess_**|set,verify|
|**_sub_**|set,verify|
|**_aud_**|set,verify|
|**_exp_**|set,verify|
|**_nbf_**|set,verify|
|**_iat_**|set,verify|
|**_jti_**|set,verify|

### How to use
Refer to tests dir

### How to build/install
#### CMake sources deps
add_subdirectory(<path to>)
#### System-wide installation
```bash
git clone https://github.com/troian/josepp
mkdir dir build && cd build
cmake -Wno-dev -DCMAKE_INSTALL_PREFIX=<install prefix> ..
make install
```

### TODO
- Documentation
- Examples
- Tests

## How to contribute
Just do it! :)
