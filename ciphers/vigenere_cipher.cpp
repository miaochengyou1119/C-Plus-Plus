/**
 * @file vigenere_cipher.cpp
 * @brief 维吉尼亚密码 (Vigenère Cipher)
 */

#include <iostream>
#include <string>
#include <cassert>

namespace ciphers {
namespace vigenere {

namespace {
// 字符转数字 A->0, B->1 ... Z->25
inline int get_value(const char c) {
    return static_cast<int>(c - 'A');
}

// 数字转回字符 0->A ... 25->Z
inline char get_char(const int x) {
    return static_cast<char>(x + 'A');
}
} // anonymous namespace

// 加密
std::string encrypt(const std::string& text, const std::string& key) {
    std::string encrypted;
    for (size_t i = 0, j = 0; i < text.size(); ++i, j = (j + 1) % key.size()) {
        int t = get_value(text[i]);
        int k = get_value(key[j]);
        encrypted += get_char((t + k) % 26);
    }
    return encrypted;
}

// 解密
std::string decrypt(const std::string& text, const std::string& key) {
    std::string decrypted;
    for (size_t i = 0, j = 0; i < text.size(); ++i, j = (j + 1) % key.size()) {
        int t = get_value(text[i]);
        int k = get_value(key[j]);
        decrypted += get_char((t - k + 26) % 26);
    }
    return decrypted;
}

} // namespace vigenere
} // namespace ciphers

// 测试
void test() {
    // 测试 1
    std::string text1 = "NIKOLATESLA";
    std::string key1 = "TESLA";
    std::string enc1 = ciphers::vigenere::encrypt(text1, key1);
    std::string dec1 = ciphers::vigenere::decrypt(enc1, key1);
    assert(text1 == dec1);

    std::cout << "原始文本: " << text1 << '\n';
    std::cout << "加密结果: " << enc1 << '\n';
    std::cout << "解密结果: " << dec1 << "\n\n";

    // 测试 2
    std::string text2 = "GOOGLEIT";
    std::string key2 = "REALLY";
    std::string enc2 = ciphers::vigenere::encrypt(text2, key2);
    std::string dec2 = ciphers::vigenere::decrypt(enc2, key2);
    assert(text2 == dec2);

    std::cout << "原始文本: " << text2 << '\n';
    std::cout << "加密结果: " << enc2 << '\n';
    std::cout << "解密结果: " << dec2 << '\n';
}

int main() {
    test();
    return 0;
}
