/**
 * @file morse_cipher.cpp
 * @brief 摩尔斯密码编码与解码
 */

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace ciphers {
namespace morse {

// 字符 -> 摩尔斯码
std::string char_to_morse(const char &c) {
    switch (c) {
        case 'a': return ".-";
        case 'b': return "-...";
        case 'c': return "-.-.";
        case 'd': return "-..";
        case 'e': return ".";
        case 'f': return "..-.";
        case 'g': return "--.";
        case 'h': return "....";
        case 'i': return "..";
        case 'j': return ".---";
        case 'k': return "-.-";
        case 'l': return ".-..";
        case 'm': return "--";
        case 'n': return "-.";
        case 'o': return "---";
        case 'p': return ".--.";
        case 'q': return "--.-";
        case 'r': return ".-.";
        case 's': return "...";
        case 't': return "-";
        case 'u': return "..-";
        case 'v': return "...-";
        case 'w': return ".--";
        case 'x': return "-..-";
        case 'y': return "-.--";
        case 'z': return "--..";
        case '1': return ".----";
        case '2': return "..---";
        case '3': return "...--";
        case '4': return "....-";
        case '5': return ".....";
        case '6': return "-....";
        case '7': return "--...";
        case '8': return "---..";
        case '9': return "----.";
        case '0': return "-----";
        default:
            std::cerr << "无效字符: " << c << '\n';
            std::exit(EXIT_FAILURE);
    }
}

// 摩尔斯码 -> 字符
char morse_to_char(const std::string &s) {
    if (s == ".-") return 'a';
    else if (s == "-...") return 'b';
    else if (s == "-.-.") return 'c';
    else if (s == "-..") return 'd';
    else if (s == ".") return 'e';
    else if (s == "..-.") return 'f';
    else if (s == "--.") return 'g';
    else if (s == "....") return 'h';
    else if (s == "..") return 'i';
    else if (s == ".---") return 'j';
    else if (s == "-.-") return 'k';
    else if (s == ".-..") return 'l';
    else if (s == "--") return 'm';
    else if (s == "-.") return 'n';
    else if (s == "---") return 'o';
    else if (s == ".--.") return 'p';
    else if (s == "--.-") return 'q';
    else if (s == ".-.") return 'r';
    else if (s == "...") return 's';
    else if (s == "-") return 't';
    else if (s == "..-") return 'u';
    else if (s == "...-") return 'v';
    else if (s == ".--") return 'w';
    else if (s == "-..-") return 'x';
    else if (s == "-.--") return 'y';
    else if (s == "--..") return 'z';
    else if (s == ".----") return '1';
    else if (s == "..---") return '2';
    else if (s == "...--") return '3';
    else if (s == "....-") return '4';
    else if (s == ".....") return '5';
    else if (s == "-....") return '6';
    else if (s == "--...") return '7';
    else if (s == "---..") return '8';
    else if (s == "----.") return '9';
    else if (s == "-----") return '0';
    else {
        std::cerr << "无效摩尔斯码: " << s << '\n';
        std::exit(EXIT_FAILURE);
    }
}

// 加密：文本 → 摩尔斯码
std::string encrypt(const std::string &text) {
    std::string encrypted;
    for (char c : text) {
        encrypted += char_to_morse(c) + " ";
    }
    return encrypted;
}

// 解密：摩尔斯码 → 文本
std::string decrypt(const std::string &text) {
    std::string decrypted;
    std::vector<std::string> parts;

    size_t start = 0, end;
    while ((end = text.find(' ', start)) != std::string::npos) {
        parts.push_back(text.substr(start, end - start));
        start = end + 1;
    }

    for (const auto &s : parts) {
        decrypted += morse_to_char(s);
    }
    return decrypted;
}

} // namespace morse
} // namespace ciphers

// 测试
void test() {
    // 数字测试
    std::string num_text = "0123456789";
    std::string num_enc = ciphers::morse::encrypt(num_text);
    std::string num_dec = ciphers::morse::decrypt(num_enc);
    assert(num_text == num_dec);

    std::cout << "==== 数字测试 ====\n";
    std::cout << "原始: " << num_text << '\n';
    std::cout << "摩斯: " << num_enc << '\n';
    std::cout << "还原: " << num_dec << "\n\n";

    // 字母测试
    std::string abc_text = "abcdefghijklmnopqrstuvwxyz";
    std::string abc_enc = ciphers::morse::encrypt(abc_text);
    std::string abc_dec = ciphers::morse::decrypt(abc_enc);
    assert(abc_text == abc_dec);

    std::cout << "==== 字母测试 ====\n";
    std::cout << "原始: " << abc_text << '\n';
    std::cout << "还原: " << abc_dec << '\n';
}

int main() {
    test();
    return 0;
}
