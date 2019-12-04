#include <phpcpp.h>
#include <sstream>
#include <iterator>
#include "xxtea.hpp"


Php::Value xxtea_encrypt(Php::Parameters &params) {

    std::string plaintext = params[0];
    std::string key = params[1];

    if (plaintext.empty()) {
        return std::string{""};
    }

    if (key.empty()) {
        throw Php::Exception("key parameter cannot be empty");
    }

    auto encrypted = xxtea::encrypt(plaintext, key);

    std::stringstream result;

    std::copy(encrypted.begin(), encrypted.end(), std::ostream_iterator<std::uint32_t>(result, " "));

    return result.str();

}


Php::Value xxtea_decrypt(Php::Parameters &params) {

    std::string encrypted = params[0];
    std::string key = params[1];

    std::istringstream is(encrypted);
    std::vector<std::uint32_t>
        decoded{std::istream_iterator<std::uint32_t>(is), std::istream_iterator<std::uint32_t>()};

    return xxtea::decrypt(decoded, key);

}

/**
 *  tell the compiler that the get_module is a pure C function
 */
extern "C" {

/**
 *  Function that is called by PHP right after the PHP process
 *  has started, and that returns an address of an internal PHP
 *  strucure with all the details and features of your extension
 *
 *  @return void*   a pointer to an address that is understood by PHP
 */
PHPCPP_EXPORT void *get_module() {
    // static(!) Php::Extension object that should stay in memory
    // for the entire duration of the process (that's why it's static)
    static Php::Extension extension("xxtea", "1.0");

    extension.add<xxtea_encrypt>("xxtea_encrypt",
                                 {Php::ByVal("data", Php::Type::String),
                                  Php::ByVal("key", Php::Type::String)});

    extension.add<xxtea_decrypt>("xxtea_decrypt",
                                 {Php::ByVal("data", Php::Type::String),
                                  Php::ByVal("key", Php::Type::String)});

    // return the extension
    return extension;
}
}
