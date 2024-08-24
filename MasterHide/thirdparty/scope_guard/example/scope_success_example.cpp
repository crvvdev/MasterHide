// Licensed under the MIT License <http://opensource.org/licenses/MIT>.
// SPDX-License-Identifier: MIT
// Copyright (c) 2018 - 2024 Daniil Goncharov <neargye@gmail.com>.
//
// Permission is hereby  granted, free of charge, to any  person obtaining a copy
// of this software and associated  documentation files (the "Software"), to deal
// in the Software  without restriction, including without  limitation the rights
// to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
// copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
// IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
// FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
// AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
// LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <scope_guard.hpp>

#include <iostream>
#include <fstream>
#include <stdexcept>

int main() {
  try {
    std::fstream file;
    file.open("test.txt", std::fstream::out | std::fstream::trunc);
    SCOPE_SUCCESS{
      file.close();
      std::cout << "[1] file write success" << std::endl;
    };

    MAKE_SCOPE_SUCCESS(scope_success_1) {
      std::cout << "[1] file write success" << std::endl;
    };

    auto scope_success_2 = scope_guard::make_scope_success([&]() {
      std::cout << "[1] file write success" << std::endl;
    });

    WITH_SCOPE_SUCCESS({ std::cout << "[1] leave WITH_SCOPE_SUCCESS" << std::endl; }) {
      std::cout << "[1] inside WITH_SCOPE_SUCCESS" << std::endl;
    }

    file << "example" << std::endl;
    std::cout << "[1] write to file" << std::endl;
    file.close();

    scope_success_1.dismiss();

    throw std::runtime_error{"error"};

    scope_success_2.dismiss();
  }
  catch (...) {
    std::cout << "[1] error" << std::endl;
  }

  std::fstream file;
  SCOPE_SUCCESS{
    file.close();
    std::cout << "[2] file write success" << std::endl;
  };
  file.open("test.txt", std::fstream::out | std::fstream::trunc);
  file << "[2] example" << std::endl;
  std::cout << "[2] write to file" << std::endl;

  return 0;

  // prints "[1] inside WITH_SCOPE_SUCCESS".
  // prints "[1] leave WITH_SCOPE_SUCCESS".
  // prints "[1] write to file".
  // prints "[1] error".
  // prints "[2] write to file".
  // prints "[2] file write success".
}
