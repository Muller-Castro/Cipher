#include <iostream>
#include <iomanip>
#include <stdlib.h>

#include "Cipher.h"

int main()
{
    try {

        using namespace encryption;

        const std::string text("Sensitive information");

        std::cout << "Text: " << text << "\n\n------\n" << std::endl;

        std::cout << std::left;

        // AES-256-CBC
        {
            const std::string key("3994160DCB240A39BA7B8B479B534DF551716BC21A66285937965C14FD7565B5"),
                              iv ("735DA18098E045F012E59B9BBA63DA69");

            auto e_text = Cipher::encrypt(text, key, iv, Cipher::KeyLength::H_256);

            auto print_e_text_info = [](const auto& e_text) {

                if(!e_text) {

                    std::cout << "Empty" << std::endl;

                    return;

                }

                constexpr int width = 30;

                std::cout << std::setw(width) << "[AES-256-CBC] Encrypted Text: " << e_text.get() << std::endl;

                std::cout << std::setw(width) << "[AES-256-CBC] Key: " << e_text.get_key() << std::endl;

                std::cout << std::setw(width) << "[AES-256-CBC] Key Length: " << static_cast<Cipher::KeyLengthBase>(e_text.get_key_length()) << " bits" << std::endl;

                std::cout << std::setw(width) << "[AES-256-CBC] IV: " << e_text.get_iv() << std::endl;

                std::cout << std::setw(width) << "[AES-256-CBC] Decrypted Text: " << Cipher::decrypt(e_text) << std::endl;

            };

            print_e_text_info(e_text);

            auto a = std::move(e_text);

            std::cout << "\nAfter moving it: ";

            print_e_text_info(e_text);
        }

        std::cout << "\n------\n" << std::endl;

        // RSA
        {
            srand(time(nullptr));

            auto e_text = Cipher::encrypt(text);
                       // Cipher::encrypt(text, seed); can be used to call 'srand(seed)' if 'seed != 1'

            auto print_e_text_info = [](const auto& e_text) {

                if(!e_text) {

                    std::cout << "Empty" << std::endl;

                    return;

                }

                auto[e, n]    = e_text.get_public_keys();
                auto[d, p, q] = e_text.get_private_keys();

                constexpr int width = 22;

                std::cout << std::setw(width) << "[RSA] Encrypted Text: " << e_text.to_str() << std::endl;

                std::cout << std::setw(width) << "[RSA] Public Keys: " << "E = " << e << ", N = " << n << std::endl;

                std::cout << std::setw(width) << "[RSA] Private Keys: " << "D = " << d << ", P = " << p << ", Q = " << q << std::endl;

                std::cout << std::setw(width) << "[RSA] Decrypted Text: " << Cipher::decrypt(e_text) << std::endl;

            };

            print_e_text_info(e_text);

            auto a = std::move(e_text);

            std::cout << "\nAfter moving it: ";

            print_e_text_info(e_text);
        }

    }catch(const std::exception& e) {

        std::cerr << "\n------\nError: " << e.what() << "\n------" << std::endl;

        return EXIT_FAILURE;

    }

    return EXIT_SUCCESS;
}
