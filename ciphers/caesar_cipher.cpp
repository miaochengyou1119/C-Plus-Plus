/**
 * @file caesar_cipher.cpp
 * @brief 凯撒密码算法实现
 */

#include <iostream>
#include <string>
#include <cassert>

namespace ciphers {
namespace caesar {

namespace {
// 数字 0~25 → 字符 A~Z
inline char get_char(const int x) {
    return static_cast<char>(x + 'A');
}

// 字符 A~Z → 数字 0~25
inline int get_value(const char c) {
    return static_cast<int>(c - 'A');
}
} // anonymous namespace

// 加密：(x + shift) % 26
std::string encrypt(const std::string& text, const int& shift) {
    std::string encrypted_text;
    for (char c : text) {
        int val = get_value(c);
        val = (val + shift) % 26;
        encrypted_text += get_char(val);
    }
    return encrypted_text;
}

// 解密：(x - shift) % 26（处理负数）
std::string decrypt(const std::string& text, const int& shift) {
    std::string decrypted_text;
    for (char c : text) {
        int val = get_value(c);
        val = (val - shift) % 26;
        if (val < 0)
            val += 26;
        decrypted_text += get_char(val);
    }
    return decrypted_text;
}

} // namespace caesar
} // namespace ciphers

// 测试函数
void test() {
    // 测试 1
    std::string text1 = "ALANTURING";
    std::string enc1 = ciphers::caesar::encrypt(text1, 17);
    std::string dec1 = ciphers::caesar::decrypt(enc1, 17);
    assert(text1 == dec1);

    std::cout << "原始文本: " << text1 << '\n';
    std::cout << "加密结果: " << enc1 << '\n';
    std::cout << "解密结果: " << dec1 << "\n\n";

    // 测试 2
    std::string text2 = "HELLOWORLD";
    std::string enc2 = ciphers::caesar::encrypt(text2, 1729);
    std::string dec2 = ciphers::caesar::decrypt(enc2, 1729);
    assert(text2 == dec2);

    std::cout << "原始文本: " << text2 << '\n';
    std::cout << "加密结果: " << enc2 << '\n';
    std::cout << "解密结果: " << dec2 << '\n';
}

int main() {
    test();
    return 0;
}
