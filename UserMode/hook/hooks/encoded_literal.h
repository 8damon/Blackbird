#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <Windows.h>
#include <cstddef>
#include <cstdint>

namespace BK_RUNTIME_INTERNAL
{
    template <std::size_t N> struct Sr71EncodedAnsiLiteral
    {
        std::uint8_t Bytes[N]{};
        std::uint8_t Key = 0;

        constexpr Sr71EncodedAnsiLiteral(const char (&literal)[N], std::uint8_t key) noexcept : Key(key)
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                Bytes[i] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(literal[i]) ^ Mask(i));
            }
        }

        constexpr std::uint8_t Mask(std::size_t index) const noexcept
        {
            return static_cast<std::uint8_t>(Key + static_cast<std::uint8_t>(index * 0x5Du) +
                                             static_cast<std::uint8_t>(index >> 1));
        }

        void Decode(char (&out)[N]) const noexcept
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                out[i] = static_cast<char>(Bytes[i] ^ Mask(i));
            }
            out[N - 1] = '\0';
        }
    };

    template <std::size_t N> struct Sr71EncodedWideLiteral
    {
        std::uint16_t Words[N]{};
        std::uint16_t Key = 0;

        constexpr Sr71EncodedWideLiteral(const wchar_t (&literal)[N], std::uint16_t key) noexcept : Key(key)
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                Words[i] = static_cast<std::uint16_t>(static_cast<std::uint16_t>(literal[i]) ^ Mask(i));
            }
        }

        constexpr std::uint16_t Mask(std::size_t index) const noexcept
        {
            return static_cast<std::uint16_t>(Key + static_cast<std::uint16_t>(index * 0x135Du) +
                                              static_cast<std::uint16_t>(index >> 1));
        }

        void Decode(wchar_t (&out)[N]) const noexcept
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                out[i] = static_cast<wchar_t>(Words[i] ^ Mask(i));
            }
            out[N - 1] = L'\0';
        }
    };

    template <std::size_t N> struct Sr71ScopedAnsiLiteral
    {
        char Value[N]{};

        explicit Sr71ScopedAnsiLiteral(const Sr71EncodedAnsiLiteral<N> &literal) noexcept
        {
            literal.Decode(Value);
        }

        ~Sr71ScopedAnsiLiteral()
        {
            SecureZeroMemory(Value, sizeof(Value));
        }

        const char *c_str() const noexcept
        {
            return Value;
        }

        operator const char *() const noexcept
        {
            return c_str();
        }
    };

    template <std::size_t N> struct Sr71ScopedWideLiteral
    {
        wchar_t Value[N]{};

        explicit Sr71ScopedWideLiteral(const Sr71EncodedWideLiteral<N> &literal) noexcept
        {
            literal.Decode(Value);
        }

        ~Sr71ScopedWideLiteral()
        {
            SecureZeroMemory(Value, sizeof(Value));
        }

        const wchar_t *c_str() const noexcept
        {
            return Value;
        }

        operator const wchar_t *() const noexcept
        {
            return c_str();
        }
    };

    template <std::size_t N>
    Sr71EncodedAnsiLiteral(const char (&literal)[N], std::uint8_t key) -> Sr71EncodedAnsiLiteral<N>;

    template <std::size_t N>
    Sr71EncodedWideLiteral(const wchar_t (&literal)[N], std::uint16_t key) -> Sr71EncodedWideLiteral<N>;

    template <std::size_t N>
    Sr71ScopedAnsiLiteral(const Sr71EncodedAnsiLiteral<N> &literal) -> Sr71ScopedAnsiLiteral<N>;

    template <std::size_t N>
    Sr71ScopedWideLiteral(const Sr71EncodedWideLiteral<N> &literal) -> Sr71ScopedWideLiteral<N>;

    inline Sr71ScopedWideLiteral<9> DecodeSr71DllName() noexcept
    {
        static constexpr Sr71EncodedWideLiteral kName{L"SR71.dll", 0x071u};
        return Sr71ScopedWideLiteral{kName};
    }

    inline Sr71ScopedWideLiteral<10> DecodeNtdllDllName() noexcept
    {
        static constexpr Sr71EncodedWideLiteral kName{L"ntdll.dll", 0x0B7u};
        return Sr71ScopedWideLiteral{kName};
    }
}
