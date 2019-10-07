#include <iostream>
#include "xxtea.hpp"
#include <vector>
#include <cstdint>



int main() {
    std::string test{"(哈)?"};
    std::string encrypted {xxtea::encrypt(test, "pass")};
    std::cout << encrypted  << '\n';
    std::cout << xxtea::decrypt(encrypted, "pass") << '\n';
    return 0;
}