/**
 * @file
 *
 * @details Implementation of 256-bit unsigned integers.
 * @note The implementation can be flagged as not completed. This header is used
 * with enough operations to demonstrate the usage of ECDH (Elliptic Curve
 * Diffie-Hellman) Key exchange.
 * @author [Ashish Daulatabad](https://github.com/AshishYUO)
 */
#include <string>
#include <utility>
#include <stdexcept>

#include "uint128_t.hpp"

#ifndef CIPHERS_UINT256_T_HPP_
#define CIPHERS_UINT256_T_HPP_

class uint256_t;

template <>
struct std::is_integral<uint256_t> : std::true_type {};

template <>
struct std::is_arithmetic<uint256_t> : std::true_type {};

template <>
struct std::is_unsigned<uint256_t> : std::true_type {};

/**
 * @class uint256_t
 * @brief class for 256-bit unsigned integer
 */
class uint256_t {
    uint128_t f{}, s{};

    /**
     * @brief Get integer from given string.
     * @details Create an integer from a given string
     * @param str integer string, can be hexadecimal (starting on 0x... or
     * number)
     * @returns void
     */
    void get_integer_from_string(const std::string &str) {
        this->f = this->s = uint128_t(0);
        if (str.size() > 1 && str[1] == 'x') {
            for (auto i = 2; i < str.size(); ++i) {
                *this *= 16ULL;
                if (str[i] >= '0' && str[i] <= '9') {
                    *this += static_cast<uint64_t>(str[i] - '0');
                } else if (str[i] >= 'A' && str[i] <= 'F') {
                    *this += static_cast<uint64_t>(str[i] - 'A' + 10);
                } else if (str[i] >= 'a' && str[i] <= 'f') {
                    *this += static_cast<uint64_t>(str[i] - 'a' + 10);
                }
            }
        } else {
            for (auto &x : str) {
                *this *= 10ULL;
                *this += static_cast<uint64_t>(x - '0');
            }
        }
    }

public:
    uint256_t() = default;

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    explicit uint256_t(T low) : f(0), s(static_cast<uint128_t>(low)) {}

    explicit uint256_t(const std::string &str) {
        get_integer_from_string(str);
    }

    uint256_t(const uint256_t &num) = default;

    uint256_t(uint256_t &&num) noexcept
        : f(std::move(num.f)), s(std::move(num.s)) {}

    uint256_t(uint128_t high, uint128_t low)
        : f(std::move(high)), s(std::move(low)) {}

    uint256_t(const uint64_t high, const uint64_t low) : f(high), s(low) {}

    ~uint256_t() = default;

    /**
     * @brief Leading zeroes in binary
     * @details Calculates leading zeros in 256-bit integer
     * @returns Integer denoting leading zeroes
     */
    inline uint32_t lez() const noexcept {
        if (f) {
            return f.lez();
        }
        return 128 + s.lez();
    }

    /**
     * @brief Trailing zeroes in binary
     * @details Calculates trailing zeros in 256-bit integer
     * @returns Integer denoting Trailing zeroes
     */
    inline uint32_t trz() const noexcept {
        if (s) {
            return s.trz();
        }
        return 128 + f.trz();
    }

    inline explicit operator bool() const noexcept { return f || s; }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline explicit operator T() const noexcept {
        return static_cast<T>(s);
    }

    inline explicit operator uint128_t() const noexcept { return s; }

    inline uint128_t lower() const noexcept { return s; }
    inline uint128_t upper() const noexcept { return f; }

    inline uint256_t &operator=(const uint256_t &p) = default;

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator=(const T &p) noexcept {
        this->s = p;
        this->f = 0;
        return *this;
    }

    inline uint256_t &operator=(const std::string &p) {
        get_integer_from_string(p);
        return *this;
    }

    inline uint256_t &operator=(uint256_t &&p) noexcept = default;

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator+(const T &p) const noexcept {
        bool app = s + p < s;
        return uint256_t(f + app, s + p);
    }

    inline uint256_t operator+(const uint256_t &p) const noexcept {
        bool app = (s + p.s < s);
        return {f + app + p.f, s + p.s};
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator+=(const T &p) noexcept {
        bool app = (p + s < s);
        this->f += app;
        this->s += p;
        return *this;
    }

    inline uint256_t &operator+=(const uint256_t &p) noexcept {
        bool app = (s + p.s < s);
        f = f + app + p.f;
        s = s + p.s;
        return *this;
    }

    inline uint256_t &operator++() noexcept {
        *this += 1ULL;
        return *this;
    }

    inline uint256_t operator++(int) noexcept {
        uint256_t temp = *this;
        ++*this;
        return temp;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator-(const T &p) const noexcept {
        bool app = (p > s);
        return uint256_t(f - app, s - p);
    }

    inline uint256_t operator-(const uint256_t &p) const noexcept {
        bool app = s < p.s;
        return {f - p.f - app, s - p.s};
    }

    inline uint256_t operator-() const noexcept {
        return ~*this + uint256_t(1ULL);
    }

    inline uint256_t &operator--() noexcept {
        *this -= 1ULL;
        return *this;
    }

    inline uint256_t operator--(int) noexcept {
        uint256_t temp = *this;
        --*this;
        return temp;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator-=(const T p) noexcept {
        bool app = (p > s);
        f = f - app;
        s = s - p;
        return *this;
    }

    inline uint256_t &operator-=(const uint256_t &p) noexcept {
        bool app = s < p.s;
        f = f - app - p.f;
        s = s - p.s;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator*(const T &p) const noexcept {
        return *this * uint256_t(p);
    }

    uint256_t operator*(const uint256_t &p) const noexcept {
        uint128_t f_first(s.upper()), f_second(s.lower());
        uint128_t s_first(p.s.upper()), s_second(p.s.lower());

        uint128_t fi = f_first * s_first;
        uint128_t se = f_first * s_second;
        uint128_t th = s_first * f_second;
        uint128_t fo = s_second * f_second;

        uint128_t tmp = se << 64;
        uint128_t tmp2 = th << 64;

        int cc = (tmp + tmp2 < tmp) ? 1 : 0;
        tmp += tmp2;
        cc += (tmp + fo < tmp) ? 1 : 0;

        return {f * p.s + s * p.f + fi + se.upper() + th.upper() + cc,
                tmp + fo};
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator*=(const T &p) noexcept {
        return (*this *= uint256_t(p));
    }

    uint256_t &operator*=(const uint256_t &p) noexcept {
        uint128_t f_first(s.upper()), f_second(s.lower());
        uint128_t s_first(p.s.upper()), s_second(p.s.lower());

        uint128_t fi = f_first * s_first;
        uint128_t se = f_first * s_second;
        uint128_t th = s_first * f_second;
        uint128_t fo = s_second * f_second;

        uint128_t tmp = se << 64;
        uint128_t tmp2 = th << 64;

        int cc = (tmp + tmp2 < tmp) ? 1 : 0;
        tmp += tmp2;
        cc += (tmp + fo < tmp) ? 1 : 0;

        f = f * p.s + s * p.f + fi + se.upper() + th.upper() + cc;
        s = tmp + fo;
        return *this;
    }

    std::pair<uint256_t, uint256_t> divide(const uint256_t &p) const {
        if (p == uint256_t(0)) {
            throw std::domain_error("Division by zero");
        }
        if (*this < p) {
            return {uint256_t(0), *this};
        } else if (*this == p) {
            return {uint256_t(1), uint256_t(0)};
        }
        uint256_t tmp = p, tmp2 = *this;
        uint16_t left = tmp.lez() - lez();
        tmp <<= left;
        uint256_t quotient(0);
        while (tmp2 >= p) {
            uint16_t shf = tmp2.lez() - tmp.lez();
            if (shf) {
                tmp >>= shf;
                quotient <<= shf;
                left -= shf;
            }
            if (tmp2 < tmp) {
                tmp >>= 1;
                quotient <<= 1;
                --left;
            }
            tmp2 -= tmp;
            ++quotient;
        }
        return {quotient << left, tmp2};
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator/(const T &p) const {
        return *this / uint256_t(p);
    }

    inline uint256_t operator/(const uint256_t &p) const {
        return divide(p).first;
    }

    inline uint256_t &operator/=(const uint256_t &p) {
        *this = divide(p).first;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator/=(const T &p) {
        *this /= uint256_t(p);
        return *this;
    }

    inline uint256_t operator%(const uint256_t &p) const {
        return divide(p).second;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator%(const T &p) const {
        return *this % uint256_t(p);
    }

    inline uint256_t &operator%=(const uint256_t &p) {
        *this = divide(p).second;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator%=(const T &p) {
        *this %= uint256_t(p);
        return *this;
    }

    inline bool operator<(const uint256_t &other) const noexcept {
        return f < other.f || (f == other.f && s < other.s);
    }

    inline bool operator<=(const uint256_t &other) const noexcept {
        return f < other.f || (f == other.f && s <= other.s);
    }

    inline bool operator>(const uint256_t &other) const noexcept {
        return f > other.f || (f == other.f && s > other.s);
    }

    inline bool operator>=(const uint256_t &other) const noexcept {
        return (f > other.f) || (f == other.f && s >= other.s);
    }

    inline bool operator==(const uint256_t &other) const noexcept {
        return f == other.f && s == other.s;
    }

    inline bool operator!=(const uint256_t &other) const noexcept {
        return !((*this) == other);
    }

    inline bool operator!() const noexcept { return !f && !s; }

    inline bool operator&&(const uint256_t &b) const noexcept {
        return (s || f) && (b.s || b.f);
    }

    inline bool operator||(const uint256_t &b) const noexcept {
        return (s || f) || (b.s || b.f);
    }

    inline bool operator()() const noexcept { return s || f; }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator<(const T &other) const noexcept {
        return *this < uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator<=(const T &other) const noexcept {
        return *this <= uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator>(const T &other) const noexcept {
        return *this > uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator>=(const T &other) const noexcept {
        return *this >= uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator==(const T &other) const noexcept {
        return *this == uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    bool operator!=(const T &other) const noexcept {
        return *this != uint256_t(other);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline bool operator&&(const T &b) const noexcept {
        return (s || f) && (b);
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline bool operator||(const T &b) const noexcept {
        return (s || f) || (b);
    }

    inline uint256_t operator~() const noexcept {
        return {~f, ~s};
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    uint256_t operator<<(const T &p) const noexcept {
        if (p == 0) {
            return *this;
        } else if (p >= 128) {
            return uint256_t((this->s << (p - 128)), uint128_t(0));
        }
        return uint256_t((this->f << p) | (this->s >> (128 - p)),
                         (this->s << p));
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    uint256_t &operator<<=(const T &p) noexcept {
        if (p == 0) return *this;
        if (p >= 128) {
            this->f = (this->s << (p - 128));
            this->s = uint128_t(0);
        } else {
            f = (this->f << p) | (this->s >> (128 - p));
            s = (this->s << p);
        }
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    uint256_t operator>>(const T &p) const noexcept {
        if (p == 0) {
            return *this;
        } else if (p >= 128) {
            return uint256_t(uint128_t(0), (this->f >> (p - 128)));
        }
        return uint256_t((this->f >> p),
                         (this->s >> p) | (this->f << (128 - p)));
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    uint256_t &operator>>=(const T &p) noexcept {
        if (p == 0) return *this;
        if (p >= 128) {
            f = uint128_t(0);
            s = (this->f >> (p - 128));
        } else {
            s = (this->s >> p) | (this->f << (128 - p));
            f = (this->f >> p);
        }
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator&(const T &p) const noexcept {
        return *this & uint256_t(p);
    }

    inline uint256_t operator&(const uint256_t &p) const noexcept {
        return {f & p.f, s & p.s};
    }

    inline uint256_t &operator&=(const uint256_t &p) noexcept {
        f &= p.f;
        s &= p.s;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator&=(const T p) noexcept {
        *this &= uint256_t(p);
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator|(const T &p) const noexcept {
        return *this | uint256_t(p);
    }

    inline uint256_t operator|(const uint256_t &p) const noexcept {
        return {this->f | p.f, this->s | p.s};
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator|=(const T &p) noexcept {
        s |= p;
        return *this;
    }

    inline uint256_t &operator|=(const uint256_t &p) noexcept {
        f |= p.f;
        s |= p.s;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t operator^(const T &p) const noexcept {
        return uint256_t(f, s ^ p);
    }

    inline uint256_t operator^(const uint256_t &p) const noexcept {
        return {this->f ^ p.f, this->s ^ p.s};
    }

    inline uint256_t &operator^=(const uint256_t &p) noexcept {
        f ^= p.f;
        s ^= p.s;
        return *this;
    }

    template <typename T, typename = typename std::enable_if<
                              std::is_integral<T>::value, T>::type>
    inline uint256_t &operator^=(const T &p) noexcept {
        s ^= p;
        return *this;
    }

    friend std::ostream &operator<<(std::ostream &op, const uint256_t &p) {
        if (!p.f) {
            op << p.s;
        } else {
            std::string out = "0";
            std::string p2 = "1";
            uint128_t L(1);
            for (uint64_t i = 0; i < 128; ++i) {
                if ((p.s & L)) {
                    out = add(out, p2);
                }
                p2 = add(p2, p2);
                L <<= 1;
            }
            L = uint128_t(1);
            for (int i = 0; i < 128; ++i) {
                if ((p.f & L)) {
                    out = add(out, p2);
                }
                p2 = add(p2, p2);
                L <<= 1;
            }
            op << out;
        }
        return op;
    }
};

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator+(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) + q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator-(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) - q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator*(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) * q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator/(const T p, const uint256_t &q) {
    return uint256_t(p) / q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator%(const T p, const uint256_t &q) {
    return uint256_t(p) % q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator&(const T &p, const uint256_t &q) noexcept {
    return uint256_t(p) & q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator|(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) | q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline uint256_t operator^(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) ^ q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator&&(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) && q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator||(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) || q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator==(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) == q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator!=(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) != q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator<(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) < q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator<=(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) <= q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator>(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) > q;
}

template <typename T, typename = typename std::enable_if<
                          std::is_integral<T>::value, T>::type>
inline bool operator>=(const T p, const uint256_t &q) noexcept {
    return uint256_t(p) >= q;
}

#endif  // CIPHERS_UINT256_T_HPP_
