# jwtpp
C++ API for JWT

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

### How to
Refer to tests dir

### TODO
- Documentation
- Examples
- Tests
