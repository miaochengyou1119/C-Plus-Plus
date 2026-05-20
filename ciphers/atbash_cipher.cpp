/**
 * @file atbash_cipher.cpp
 * @brief 阿特巴什密码（反转字母表）
 */

#include <iostream>
#include <string>
#include <cassert>
#include <cctype>

namespace ciphers {
namespace atbash {

// 加密 = 解密（对称）
std::string atbash(const std::string& text) {
    std::string result;
    for (unsigned char c : text) {
        if (std::isalpha(c)) {
            if (std::isupper(c)) {
                // 大写：A ↔ Z，B ↔ Y ...
                result += 'Z' - (c - 'A');
            } else {
                // 小写：a ↔ z，b ↔ y ...
                result += 'z' - (c - 'a');
            }
        } else {
            // 非字母直接保留
            result += c;
        }
    }
    return result;
}

} // namespace atbash
} // namespace ciphers

// 测试
void test() {
    std::string text = "Hello World";
    std::string expect = "Svool Dliow";

    std::string enc = ciphers::atbash::atbash(text);
    std::string dec = ciphers::atbash::atbash(enc);

    std::cout << "原始文本: " << text << '\n';
    std::cout << "加密结果: " << enc << '\n';
    std::cout << "解密结果: " << dec << '\n';

    assert(enc == expect);
    assert(dec == text);

    std::cout << "\n✅ Atbash 密码测试通过！\n";
}

int main() {
    test();
    return 0;
}
