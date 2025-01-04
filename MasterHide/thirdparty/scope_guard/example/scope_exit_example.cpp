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

#include <iostream>
#include <fstream>
#include <stdexcept>

#define SCOPE_GUARD_SUPPRESS_THROW_ACTION
#define SCOPE_GUARD_CATCH_HANDLER std::cout << "exception in scope_guard!" << std::endl;

#include <scope_guard.hpp>

int main() {
  try {
    std::fstream file;
    file.open("test.txt", std::fstream::out | std::fstream::trunc);
    SCOPE_EXIT{
      file.close();
      std::cout << "[1] close file" << std::endl;
      throw std::runtime_error{"error close file"};
    };

    MAKE_SCOPE_EXIT(scope_exit_1) {
      file.close();
      std::cout << "[1] close file #1" << std::endl;
    };

    auto scope_exit_2 = scope_guard::make_scope_exit([&]() {
      file.close();
      std::cout << "[1] close file #2" << std::endl;
    });

    WITH_SCOPE_EXIT({ std::cout << "[1] leave WITH_SCOPE_EXIT" << std::endl; }) {
      std::cout << "[1] inside WITH_SCOPE_EXIT" << std::endl;
    }

    file << "example" << std::endl;
    std::cout << "[1] write to file" << std::endl;

    scope_exit_1.dismiss();

    throw std::runtime_error{"error"};

    scope_exit_2.dismiss();

    file.close();
  }
  catch (...) {
    std::cout << "[1] error" << std::endl;
  }

  std::fstream file;
  SCOPE_EXIT{
    file.close();
    std::cout << "[2] close file" << std::endl;
  };
  file.open("test.txt", std::fstream::out | std::fstream::trunc);
  file << "[2] example" << std::endl;
  std::cout << "[2] write to file" << std::endl;
  file.close();

  return 0;

  // prints "[1] inside WITH_SCOPE_EXIT".
  // prints "[1] leave WITH_SCOPE_EXIT".
  // prints "[1] write to file".
  // prints "[1] close file #2".
  // prints "[1] close file".
  // prints "[1] error".
  // prints "[2] write to file".
  // prints "[2] close file".
}
