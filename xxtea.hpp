#pragma once
#include "utf8.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <array>
/**
 * XXTEA encryption algorithm library for C++.
 *
 * Encryption Algorithm Authors:
 *       David J. Wheeler
 *       Roger M. Needham
 *
 * Code Author: Gabriel Menezes <https://github.com/menezes-/xxtea>
 */

namespace xxtea
{

namespace base64
{
// taken from here with small modifitications https://vorbrodt.blog/2019/03/23/base64-encoding/

// uses url and filename safe version per rfc 4648
constexpr std::array<char, 64> encode_lookup =
    {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
     'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
     'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'};

constexpr auto pad_char = '=';

using byte = std::uint32_t;


inline std::string encode(const std::vector<byte> &input) {
    std::string encoded;
    auto t = (input.size() % 3 > 0) ? 1 : 0;
    encoded.reserve(((input.size() / 3) + t) * 4);

    std::uint32_t temp{};
    auto it = input.begin();

    for (std::size_t i = 0; i < input.size() / 3; ++i) {
        temp = (*it++) << 16U;
        temp += (*it++) << 8U;
        temp += (*it++);
        encoded.append(1, encode_lookup[(temp & 0x00FC0000U) >> 18U]);
        encoded.append(1, encode_lookup[(temp & 0x0003F000U) >> 12U]);
        encoded.append(1, encode_lookup[(temp & 0x00000FC0U) >> 6U]);
        encoded.append(1, encode_lookup[(temp & 0x0000003FU)]);
    }

    switch (input.size() % 3) {
        case 1:
            temp = (*it++) << 16U;
            encoded.append(1, encode_lookup[(temp & 0x00FC0000U) >> 18U]);
            encoded.append(1, encode_lookup[(temp & 0x0003F000U) >> 12U]);
            encoded.append(2, pad_char);
            break;
        case 2:
            temp = (*it++) << 16U;
            temp += (*it++) << 8U;
            encoded.append(1, encode_lookup[(temp & 0x00FC0000U) >> 18U]);
            encoded.append(1, encode_lookup[(temp & 0x0003F000U) >> 12U]);
            encoded.append(1, encode_lookup[(temp & 0x00000FC0U) >> 6U]);
            encoded.append(1, pad_char);
            break;
    }

    return encoded;
}


std::vector<byte> decode(const std::string &input) {
    if (input.length() % 4 > 0) {
        throw std::runtime_error("Invalid base64 length!");
    }

    std::size_t padding{};

    if (!input.empty()) {
        if (input[input.length() - 1] == pad_char) {
            padding++;
        }
        if (input[input.length() - 2] == pad_char) {
            padding++;
        }
    }

    std::vector<byte> decoded;
    decoded.reserve(((input.length() / 4) * 3) - padding);

    std::uint32_t temp{};
    auto it = input.begin();

    while (it < input.end()) {
        for (std::size_t i = 0; i < 4; ++i) {
            temp <<= 6U;
            if (*it >= 0x41 && *it <= 0x5A) {
                temp |= *it - 0x41U;
            } else if (*it >= 0x61 && *it <= 0x7A) {
                temp |= *it - 0x47U;
            } else if (*it >= 0x30 && *it <= 0x39) {
                temp |= *it + 0x04U;
            } else if (*it == 0x2B) {
                temp |= 0x3EU;
            } else if (*it == 0x2F) {
                temp |= 0x3FU;
            } else if (*it == pad_char) {
                switch (input.end() - it) {
                    case 1:
                        decoded.push_back((temp >> 16U) & 0xFFU);
                        decoded.push_back((temp >> 8U) & 0xFFU);
                        return decoded;
                    case 2:
                        decoded.push_back((temp >> 10U) & 0xFFU);
                        return decoded;
                    default:
                        throw std::runtime_error("Invalid padding in base64!");
                }
            } else {
                throw std::runtime_error("Invalid character in base64!");
            }

            ++it;
        }

        decoded.push_back((temp >> 16U) & 0x0FFU);
        decoded.push_back((temp >> 8U) & 0xFFU);
        decoded.push_back((temp) & 0xFFU);
    }

    return decoded;
}

}
using bytes = std::vector<std::uint32_t>;

namespace internal
{

inline bytes decode_utf8(const std::string &bytes) {
    std::vector<std::uint32_t> stream{};
    utf8::utf8to32(bytes.begin(), bytes.end(), std::back_inserter(stream));
    return stream;
}


inline std::string encode_utf8(const bytes &wstr) {
    std::vector<std::uint32_t> stream{};

    utf8::utf32to8(wstr.begin(), wstr.end(), std::back_inserter(stream));
    return {stream.begin(), stream.end()};
}


inline void pad_vector(bytes &bytes, std::size_t min_len) {
    if (bytes.size() < min_len) {
        bytes.resize(min_len - bytes.size(), std::uint32_t{0});
    }
}


inline void fixk(bytes &k) {
    if  (k.size() > 4){
        k.resize(4);
    }
}


constexpr uint32_t delta{0x9E3779B9};

}
// acording to this stackexchange https://crypto.stackexchange.com/a/12997 comment
// xxtea security can be increase by increasing the number of mixes,
// so i've put this as a definibable constant
#ifndef XXTEA_NUMBER_OF_MIXES
#define XXTEA_NUMBER_OF_MIXES 6
#endif

#define XXTEA_MX(sum, y, z, p, e, k) ((z >> 5U ^ y << 2U) + (y >> 3U ^ z << 4U)) ^ ((sum ^ y) + (k[(p & 3U) ^ e] ^ z));


/**
 * encodes an array of unsigned 32-bit integers using 128-bit key.
 * @param v vector of uint32
 * @param k 128-bit key, if smaller the vector will be padded
 */
inline void encode(bytes &v, bytes &k) {
    if (v.empty()) {
        return;
    }
    if (v.size() < 2) {
        internal::pad_vector(v, 2);
    }

    auto length = v.size();
    auto n = static_cast<std::uint32_t >(length - 1);
    internal::pad_vector(k, 4);

    std::uint32_t y;
    std::uint32_t z{v[n]};
    std::uint32_t sum{0};
    std::uint32_t e;
    std::uint32_t p{0};
    std::uint32_t q;


    for (q = XXTEA_NUMBER_OF_MIXES + 52 / length; q > 0; --q) {
        sum += internal::delta;
        e = sum >> 2U & 3U;
        for (; p < n; ++p) {
            y = v[p + 1];
            v[p] += XXTEA_MX(sum, y, z, p, e, k);
            z = v[p];
        }
        y = v[0];
        v[n] += XXTEA_MX(sum, y, z, p, e, k);
        z = v[n];
    }

}


/**
 * decodes an array of unsigned 32-bit integers using 128-bit key.
 * @param v array to be decoded
 * @param k 128-bit key
 */
inline void decode(bytes &v, bytes &k) {
    if (v.empty()) {
        return;
    }
    if (v.size() < 2) {
        internal::pad_vector(v, 2);
    }

    auto length = v.size();
    auto n = static_cast<std::uint32_t >(length - 1);
    internal::pad_vector(k, 4);
    std::uint32_t y{v[0]};
    std::uint32_t z;
    std::uint32_t sum;
    std::uint32_t e;
    std::uint32_t p;
    std::uint32_t q = XXTEA_NUMBER_OF_MIXES + 52 / length;


    for (sum = q * internal::delta; sum != 0; sum -= internal::delta) {
        e = sum >> 2U & 3U;
        for (p = n; p > 0; --p) {
            z = v[p - 1];
            v[p] -= XXTEA_MX(sum, y, z, p, e, k);
            y = v[p];
        }
        z = v[n];
        v[0] -= XXTEA_MX(sum, y, z, p, e, k);
        y = v[0];

    }

}


/**
 *  Encrypts text using Corrected Block TEA (aka xxtea) algorithm
 * @param plaintext String to be encrypted. Handles utf-8.
 * @param password Password to be used for encryption (only 128 bits are used).
 * @return Encrypted text encoded as safe base 64 string (per rfc 4648)
 */
inline std::string encrypt(const std::string &plaintext, const std::string &password) {
    auto text = internal::decode_utf8(plaintext);
    auto key = internal::decode_utf8(password);

    internal::fixk(key);

    encode(text, key);

    return base64::encode(text);

}


/**
 * Decrypts text using Corrected Block TEA (xxtea) algorithm
 * @param encrypted_string safe base64 (rfc 4648) encrypted string @see encrypt
 * @param password password used to encrypt the string
 * @return utf8 encoded string
 */
inline std::string decrypt(const std::string &encrypted_string, const std::string &password) {
    auto decoded = base64::decode(encrypted_string);
    auto key = internal::decode_utf8(password);

    internal::fixk(key);

    decode(decoded, key);

    return internal::encode_utf8(decoded);

}

}