/****************************************************************************************/
/* Copyright (c) 2021 Muller Castro                                                     */
/*                                                                                      */
/* Permission is hereby granted, free of charge, to any person obtaining                */
/* a copy of this software and associated documentation files (the "Software"),         */
/* to deal in the Software without restriction, including without limitation            */
/* the rights to use, copy, modify, merge, publish, distribute, sublicense,             */
/* and/or sell copies of the Software, and to permit persons to whom the Software       */
/* is furnished to do so, subject to the following conditions:                          */
/*                                                                                      */
/* The above copyright notice and this permission notice shall be included in all       */
/* copies or substantial portions of the Software.                                      */
/*                                                                                      */
/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,  */
/* INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A        */
/* PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT   */
/* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF */
/* CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE */
/* OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                                        */
/****************************************************************************************/

#ifndef CIPHER_H
#define CIPHER_H

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <stdexcept>

#include "AES.h"
#include "RSA.h"

namespace encryption {

    class Cipher final
    {
    public:
        enum class KeyLength : unsigned short
        {
            H_256 = 256,
            M_192 = 192,
            S_128 = 128
        };

        class AESEncryptedText final
        {
        public:
            explicit operator bool() const noexcept { return !text.empty(); }

            operator std::string() const { return text; }

            constexpr KeyLength get_key_length() const noexcept { return key_length; }

            constexpr const std::string& get()     const noexcept { return text; }
            constexpr const std::string& get_key() const noexcept { return key;  }
            constexpr const std::string& get_iv()  const noexcept { return iv;   }

        private:
            friend class Cipher;

            KeyLength key_length;

            std::string text, key, iv;

            AESEncryptedText(std::string_view text_, std::string_view key_, std::string_view iv_, KeyLength key_length_) :
                key_length(key_length_),
                text(text_),
                key(key_),
                iv(iv_)
            {
                //
            }
        };

        class RSAEncryptedText final
        {
        public:
            struct PublicKeys final
            {
                unsigned long long e, n;
            };

            struct PrivateKeys final
            {
                unsigned long long d, p, q;
            };

            explicit operator bool() const noexcept { return !text.empty(); }

            operator std::string() const { return to_str(); }

            constexpr const std::vector<RSA::ULL>& get() const noexcept { return text; }

            constexpr const PublicKeys& get_public_keys() const noexcept { return public_keys; };

            constexpr const PrivateKeys& get_private_keys() const noexcept { return private_keys; };

            std::string to_str() const { return std::string(text.cbegin(), text.cend()); };

        private:
            friend class Cipher;

            std::vector<RSA::ULL> text;

            PublicKeys public_keys;

            PrivateKeys private_keys;

            RSAEncryptedText(const std::vector<RSA::ULL>& text_, const PublicKeys& public_keys_, const PrivateKeys& private_keys_) :
                text(text_),
                public_keys(public_keys_),
                private_keys(private_keys_)
            {
                //
            }
        };

        static AESEncryptedText encrypt(std::string_view text, std::string_view key, std::string_view iv, KeyLength kl)
        {
            if(text.empty()) throw std::runtime_error("The text can't be empty");

            if((iv.length() != 16) && (iv.length() != 24) && (iv.length() != 32)) throw std::runtime_error("The initialization vector (IV) must be either 16, 24 or 32 bytes long");

            const char* data = text.data();
            size_t length    = text.length();

            std::string padded_text{};

            switch(kl) {

                case KeyLength::H_256: {

                    if(key.length() < 32) throw std::runtime_error("The key must be at least 32 bytes long for KeyLength::H_256");

                    if     (length < 32) Cipher::pad_text(padded_text = std::string(text) + '\0', data, length, 32);
                    else if(length > 32) throw std::runtime_error("The text can't be greater than 32 bytes long for KeyLength::H_256");

                } break;

                case KeyLength::M_192: {

                    if(key.length() < 24) throw std::runtime_error("The key must be at least 24 bytes long for KeyLength::M_192");

                    if     (length < 24) Cipher::pad_text(padded_text = std::string(text) + '\0', data, length, 24);
                    else if(length > 24) throw std::runtime_error("The text can't be greater than 24 bytes long for KeyLength::M_192");

                } break;

                case KeyLength::S_128: {

                    if(key.length() < 16) throw std::runtime_error("The key must be at least 16 bytes long for KeyLength::S_128");

                    if     (length < 16) Cipher::pad_text(padded_text = std::string(text) + '\0', data, length, 16);
                    else if(length > 16) throw std::runtime_error("The text can't be greater than 16 bytes long for KeyLength::S_128");

                } break;

                default: throw std::runtime_error("Key length not supported");

            }

            unsigned out_len{};

            std::unique_ptr<const unsigned char[]> output(

                AES(static_cast<unsigned short>(kl)).EncryptCBC(

                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(data)),
                    sizeof(unsigned char) * length,
                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(key.data())),
                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(iv.data())),
                    out_len

                )

            );

            const AESEncryptedText result(reinterpret_cast<const char*>(output.get()), key, iv, kl);

            output.reset();

            return result;
        }

        static RSAEncryptedText encrypt(std::string_view text, unsigned seed = 1)
        {
            if(text.empty()) throw std::runtime_error("The text can't be empty");

            if(seed != 1) srand(seed);

            RSA rsa{};

            RSA::ULL _e{}, _n{}, _d{}, _p{}, _q{};

            rsa.get_public_key(_e, _n);

            rsa.get_private_key(_d, _p, _q);

            std::vector<RSA::ULL> bin_text(text.cbegin(), text.cend()), output(text.length());

            RSA::cipher(bin_text.data(), bin_text.size(), output.data(), _e, _n);

            return {output, {_e, _n}, {_d, _p, _q}};
        }

        static std::string decrypt(const AESEncryptedText& e_text)
        {
            if(!e_text) return {};

            const auto key_length_value = static_cast<unsigned short>(e_text.get_key_length());

            const auto length = key_length_value >> 3;

            std::unique_ptr<const unsigned char[]> output(

                AES(key_length_value).DecryptCBC(

                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(e_text.get().data())),
                    sizeof(unsigned char) * length,
                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(e_text.get_key().data())),
                    const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(e_text.get_iv().data()))

                )

            );

            const std::string result(reinterpret_cast<const char*>(output.get()));

            output.reset();

            return result.substr(0, length);
        }

        static std::string decrypt(const RSAEncryptedText& e_text)
        {
            if(!e_text) return {};

            decltype(auto) bin_text    = e_text.get();
            decltype(auto) private_key = e_text.get_private_keys();

            auto output = bin_text;

            RSA::decipher(bin_text.data(), bin_text.size(), output.data(), private_key.d, private_key.p, private_key.q);

            return std::string(output.cbegin(), output.cend());
        }

    private:
        static void pad_text(std::string& text, const char*& data, size_t& length, size_t align_length)
        {
            while(text.length() % align_length != 0) text += '\0';

            data   = text.c_str();
            length = text.length();
        }
    };

}

#endif // CIPHER_H
