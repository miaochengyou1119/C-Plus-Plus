/**
 * @file xor_cipher.cpp
 * @brief XOR cipher 加密解密算法
 */

#include <iostream>
#include <string>
#include <cassert>

namespace ciphers {
namespace XOR {

// 加密：对每个字符与 key 异或
std::string encrypt(const std::string &text, const int &key) {
    std::string encrypted_text;
    for (char c : text) {
        encrypted_text += char(c ^ key);
    }
    return encrypted_text;
}

// 解密：与加密完全相同（异或两次恢复原文）
std::string decrypt(const std::string &text, const int &key) {
    return encrypt(text, key);
}

} // namespace XOR
} // namespace ciphers

// 测试函数
void test() {
    // 测试 1
    std::string text1 = "Whipalsh! : Do watch this movie...";
    std::string encrypted1 = ciphers::XOR::encrypt(text1, 17);
    std::string decrypted1 = ciphers::XOR::decrypt(encrypted1, 17);
    assert(text1 == decrypted1);

    std::cout << "原始文本: " << text1 << std::endl;
    std::cout << "加密文本: " << encrypted1 << std::endl;
    std::cout << "解密文本: " << decrypted1 << std::endl << std::endl;

    // 测试 2
    std::string text2 = "->Valar M0rghulis<-";
    std::string encrypted2 = ciphers::XOR::encrypt(text2, 29);
    std::string decrypted2 = ciphers::XOR::decrypt(encrypted2, 29);
    assert(text2 == decrypted2);

    std::cout << "原始文本: " << text2 << std::endl;
    std::cout << "加密文本: " << encrypted2 << std::endl;
    std::cout << "解密文本: " << decrypted2 << std::endl;
}

int main() {
    test();
    return 0;
}
