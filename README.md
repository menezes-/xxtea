# xxtea
Implementation of the [corrected Block TEA](https://en.wikipedia.org/wiki/XXTEA) encryption algorithm in modern C++. 

It focuses on encrypting strings but it can be easily modified to encrypt binary data (take a look at the `encode` and `decode` functions).

This is a header only library so you just need to copy `xxtea.hpp` to your src folder and `#include` it.

## Usage

```cpp
#include <iostream>
#include "xxtea.hpp"

int main() {
  std::string secret{"super secret string"};
  
  auto encrypted = xxtea::encrypt(test, "hunter2");
  // encrypted is a std::vector<std::uint32_t>, you can serialize however you want (an example of that is in the xxtea-php.cpp file)
  // if your password is less than 128 bits it will be padded
  
  std::cout << xxtea::decrypt(encrypted, "hunter2") << '\n';
  
  return 0;
}
```

## PHP extension

There's also a PHP extension inside xxtea-php, you can compile it using CMake. To be able to compile it you must have [PHP-CPP](https://github.com/CopernicaMarketingSoftware/PHP-CPP) installed.

