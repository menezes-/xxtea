#pragma once

// taken from here with small modifitications https://vorbrodt.blog/2019/03/23/base64-encoding/

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <array>

namespace base64
{

constexpr std::array<char, 64> kEncodeLookup =
    {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
     'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
     'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

constexpr auto kPadCharacter = '=';

using byte = std::uint8_t;


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
        encoded.append(1, kEncodeLookup[(temp & 0x00FC0000U) >> 18U]);
        encoded.append(1, kEncodeLookup[(temp & 0x0003F000U) >> 12U]);
        encoded.append(1, kEncodeLookup[(temp & 0x00000FC0U) >> 6U]);
        encoded.append(1, kEncodeLookup[(temp & 0x0000003FU)]);
    }

    switch (input.size() % 3) {
        case 1:
            temp = (*it++) << 16U;
            encoded.append(1, kEncodeLookup[(temp & 0x00FC0000U) >> 18U]);
            encoded.append(1, kEncodeLookup[(temp & 0x0003F000U) >> 12U]);
            encoded.append(2, kPadCharacter);
            break;
        case 2:
            temp = (*it++) << 16U;
            temp += (*it++) << 8U;
            encoded.append(1, kEncodeLookup[(temp & 0x00FC0000U) >> 18U]);
            encoded.append(1, kEncodeLookup[(temp & 0x0003F000U) >> 12U]);
            encoded.append(1, kEncodeLookup[(temp & 0x00000FC0U) >> 6U]);
            encoded.append(1, kPadCharacter);
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
        if (input[input.length() - 1] == kPadCharacter) {
            padding++;
        }
        if (input[input.length() - 2] == kPadCharacter) {
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
            } else if (*it == kPadCharacter) {
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