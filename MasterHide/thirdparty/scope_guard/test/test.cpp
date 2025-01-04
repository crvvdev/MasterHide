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

#define CATCH_CONFIG_MAIN
#include <catch.hpp>

#define TROMPELOEIL_SANITY_CHECKS
#include <trompeloeil.hpp>
#include <catch_trompeloeil.hpp>

#define SCOPE_GUARD_NO_THROW_CONSTRUCTIBLE
#include <scope_guard.hpp>

#include <stdexcept>

struct ExecutionCounter {
  MAKE_MOCK0(Execute, void());
};

class F {
public:
  F() = default;
  F(F&&) = default;
  F(const F&) = default;
  ~F() = default;
  F& operator=(const F&) = default;
  F& operator=(F&&) = default;

  void operator() () {}
};

TEST_CASE("called on scope leave") {
  SECTION("scope_exit") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_NOTHROW([&]() {
      SCOPE_EXIT{ m.Execute(); };
    }());
  }

  SECTION("scope_fail") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_NOTHROW([&]() {
      SCOPE_FAIL{ m.Execute(); };
    }());
  }

  SECTION("scope_success") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_NOTHROW([&]() {
      SCOPE_SUCCESS{ m.Execute(); };
    }());
  }
}

TEST_CASE("called on exception") {
  SECTION("scope_exit") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_THROWS([&]() {
      SCOPE_EXIT{ m.Execute(); };

      throw std::exception{};
    }());
  }

  SECTION("scope_fail") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_THROWS([&]() {
      SCOPE_FAIL{ m.Execute(); };

      throw std::exception{};
    }());
  }

  SECTION("scope_success") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_THROWS([&]() {
      SCOPE_SUCCESS{ m.Execute(); };

      throw std::exception{};
    }());
  }
}

TEST_CASE("dismiss before scope leave") {
  SECTION("scope_exit") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_NOTHROW([&]() {
      MAKE_SCOPE_EXIT(sg){ m.Execute(); };
      sg.dismiss();
    }());
  }

  SECTION("scope_fail") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_NOTHROW([&]() {
      MAKE_SCOPE_FAIL(sg){ m.Execute(); };
      sg.dismiss();
    }());
  }

  SECTION("scope_success") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_NOTHROW([&]() {
      MAKE_SCOPE_SUCCESS(sg){ m.Execute(); };
      sg.dismiss();
    }());
  }
}

TEST_CASE("dismiss before exception") {
  SECTION("scope_exit") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_EXIT(sg){ m.Execute(); };

      sg.dismiss();

      throw std::exception{};
    }());
  }

  SECTION("scope_fail") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_FAIL(sg){ m.Execute(); };

      sg.dismiss();

      throw std::exception{};
    }());
  }

  SECTION("scope_success") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_SUCCESS(sg){ m.Execute(); };

      sg.dismiss();

      throw std::exception{};
    }());
  }
}

TEST_CASE("called on exception, dismiss after exception") {
  SECTION("scope_exit") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_EXIT(sg){ m.Execute(); };

      throw std::exception{};

      sg.dismiss();
    }());
  }

  SECTION("scope_fail") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(1));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_FAIL(sg){ m.Execute(); };

      throw std::exception{};

      sg.dismiss();
    }());
  }

  SECTION("scope_success") {
    ExecutionCounter m;
    REQUIRE_CALL_V(m, Execute(),
                   .TIMES(0));

    REQUIRE_THROWS([&]() {
      MAKE_SCOPE_SUCCESS(sg){ m.Execute(); };

      throw std::exception{};

      sg.dismiss();
    }());
  }
}
