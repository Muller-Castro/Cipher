# Cipher
A C++17 wrapper for the AES-128/192/256 (all CBC) and RSA encryption systems

The **Cipher** class is intended to be a secure and very easy-to-use interface:

**AES**
```c++
using namespace encryption;

const std::string text("Sensitive information");

const std::string key("3994160DCB240A39BA7B8B479B534DF551716BC21A66285937965C14FD7565B5"),
		  iv ("735DA18098E045F012E59B9BBA63DA69");

auto e_text = Cipher::encrypt(text, key, iv, Cipher::KeyLength::H_256);

assert(Cipher::decrypt(e_text) == text);
```

**RSA**
```c++
using namespace encryption;

const std::string text("Sensitive information");

srand(time(nullptr));

auto e_text = Cipher::encrypt(text);
	   // Cipher::encrypt(text, seed); can be used to call 'srand(seed)' if 'seed != 1'

assert(Cipher::decrypt(e_text) == text);
```

Please see the **Main.cpp** file for more details.
