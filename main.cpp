#include <iostream>
#include "xxtea.hpp"
#include <vector>
#include <cstdint>



int main() {
    std::string test{"teste"};

    auto encrypted = xxtea::encrypt(test, "pasass");
    std::cout << xxtea::decrypt(encrypted, "pasass") << '\n';




    return 0;
}