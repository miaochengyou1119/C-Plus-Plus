/**
 * @file base64_encoding.cpp
 * @brief Base64 编码与解码（标准 RFC4648）
 */

#include <iostream>
#include <string>
#include <cassert>

namespace ciphers {
namespace base64 {

const std::string chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 编码
std::string encode(const std::string& input) {
    std::string out;
    for (size_t i = 0; i < input.size(); i += 3) {
        uint8_t b1 = input[i];
        out += chars[(b1 >> 2) & 0x3F];

        if (i + 1 < input.size()) {
            uint8_t b2 = input[i + 1];
            out += chars[((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)];

            if (i + 2 < input.size()) {
                uint8_t b3 = input[i + 2];
                out += chars[((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)];
                out += chars[b3 & 0x3F];
            } else {
                out += chars[(b2 & 0x0F) << 2];
                out += '=';
            }
        } else {
            out += chars[(b1 & 0x03) << 4];
            out += '=';
            out += '=';
        }
    }
    return out;
}

// 查找字符索引
uint8_t find_idx(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0;
}

// Base64 解码
std::string decode(const std::string& input) {
    std::string out;
    for (size_t i = 0; i < input.size(); i += 4) {
        uint8_t c1 = find_idx(input[i]);
        uint8_t c2 = find_idx(input[i + 1]);
        out += (c1 << 2) | ((c2 >> 4) & 0x03);

        if (input[i + 2] != '=') {
            uint8_t c3 = find_idx(input[i + 2]);
            out += ((c2 & 0x0F) << 4) | ((c3 >> 2) & 0x0F);

            if (input[i + 3] != '=') {
                uint8_t c4 = find_idx(input[i + 3]);
                out += ((c3 & 0x03) << 6) | c4;
            }
        }
    }
    return out;
}

} // namespace base64
} // namespace ciphers

// 测试
void test() {
    std::string text = "Base64 is a group of binary-to-text encoding schemes.";
    std::string enc = ciphers::base64::encode(text);
    std::string dec = ciphers::base64::decode(enc);

    std::cout << "原始文本: " << text << "\n";
    std::cout << "Base64编码: " << enc << "\n";
    std::cout << "解码结果: " << dec << "\n\n";

    assert(dec == text);
    std::cout << "✅ Base64 编码/解码测试通过！\n";
}

int main() {
    test();
    return 0;
}
