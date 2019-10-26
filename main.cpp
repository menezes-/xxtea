#include <iostream>
#include "xxtea.hpp"
#include <vector>
#include <cstdint>
#include <sstream>
#include <iterator>



int main() {
    std::string test{"teste"};

    auto encrypted = xxtea::encrypt(test, "pasass");

    std::stringstream result;

    std::copy(encrypted.begin(), encrypted.end(), std::ostream_iterator<std::uint32_t>(result, " "));

    std::cout << result.str() << '\n';

    std::istringstream is(result.str());
    std::vector<std::uint32_t>
        decoded{std::istream_iterator<std::uint32_t>(is), std::istream_iterator<std::uint32_t>()};

    std::cout << xxtea::decrypt(decoded, "pasass") << '\n';





    return 0;
}