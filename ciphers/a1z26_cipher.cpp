/**
 * @file a1z26_cipher.cpp
 * @brief A1Z26 字母数字密码（A=1, B=2 ... Z=26）
 */

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cassert>
#include <cctype>

namespace ciphers {
namespace a1z26 {

// 加密：字母 → 数字（用 - 分隔）
std::string encrypt(const std::string& text) {
    std::string res;
    for (char c : text) {
        if (c == ' ') {
            res += ' ';
            continue;
        }
        int num = tolower(c) - 'a' + 1;
        res += std::to_string(num) + "-";
    }
    if (!res.empty() && res.back() == '-')
        res.pop_back();

    // 把 "- " 换成 " "
    size_t pos;
    while ((pos = res.find("- ")) != std::string::npos)
        res.replace(pos, 2, " ");
    return res;
}

// 解密：数字 → 字母
std::string decrypt(const std::string& text, bool uppercase = false) {
    std::string res;
    std::stringstream ss(text);
    std::string part;

    while (std::getline(ss, part, ' ')) {
        std::stringstream ss2(part);
        std::string num_str;
        while (std::getline(ss2, num_str, '-')) {
            int num = std::stoi(num_str);
            char c = 'a' + num - 1;
            res += c;
        }
        res += ' ';
    }
    if (!res.empty())
        res.pop_back();

    if (uppercase)
        std::transform(res.begin(), res.end(), res.begin(), ::toupper);
    return res;
}

} // namespace a1z26
} // namespace ciphers

// 测试
void test() {
    // 测试 1：加密
    std::string text = "Hello World";
    std::string expect_enc = "8-5-12-12-15 23-15-18-12-4";
    std::string enc = ciphers::a1z26::encrypt(text);
    assert(enc == expect_enc);

    // 测试 2：解密小写
    std::string enc_text = "12-15-23-5-18-3-1-19-5";
    std::string expect_dec = "lowercase";
    std::string dec = ciphers::a1z26::decrypt(enc_text);
    assert(dec == expect_dec);

    // 测试 3：解密大写
    std::string enc2 = "21-16-16-5-18-3-1-19-5";
    std::string expect_upper = "UPPERCASE";
    std::string dec_upper = ciphers::a1z26::decrypt(enc2, true);
    assert(dec_upper == expect_upper);

    std::cout << "✅ 所有 A1Z26 测试通过！\n";
    std::cout << "原文: " << text << "\n";
    std::cout << "加密: " << enc << "\n";
    std::cout << "解密: " << ciphers::a1z26::decrypt(enc) << "\n";
}

int main() {
    test();
    return 0;
}
