[![Github Releases](https://img.shields.io/github/release/Neargye/scope_guard.svg)](https://github.com/Neargye/scope_guard/releases)
[![License](https://img.shields.io/github/license/Neargye/scope_guard.svg)](LICENSE)

# Scope Guard & Defer C++

Scope Guard statement invokes a function with deferred execution until surrounding function returns in cases:

* scope_exit - executing action on scope exit.

* scope_fail - executing action on scope exit when an exception has been thrown.

* scope_success - executing action on scope exit when no exceptions have been thrown.

Program control transferring does not influence Scope Guard statement execution. Hence, Scope Guard statement can be used to perform manual resource management, such as file descriptors closing, and to perform actions even if an error occurs.

## Features

* C++11
* Header-only
* Dependency-free
* Thin callback wrapping, no added std::function or virtual table penalties
* No implicitly ignored return, check callback return void
* Defer or Scope Guard syntax and "With" syntax

## [Examples](example)

* [Scope Guard on exit](example/scope_exit_example.cpp)

  ```cpp
  std::fstream file("test.txt");
  SCOPE_EXIT{ file.close(); }; // File closes when exit the enclosing scope or errors occur.
  ```

* [Scope Guard on fail](example/scope_fail_example.cpp)

  ```cpp
  persons.push_back(person); // Add the person to db.
  SCOPE_FAIL{ persons.pop_back(); }; // If errors occur, we should roll back.
  ```

* [Scope Guard on success](example/scope_success_example.cpp)

  ```cpp
  person = new Person{/*...*/};
  // ...
  SCOPE_SUCCESS{ persons.push_back(person); }; // If no errors occur, we should add the person to db.
  ```

* Custom Scope Guard

  ```cpp
  persons.push_back(person); // Add the person to db.

  MAKE_SCOPE_EXIT(scope_exit) { // Following block is executed when exit the enclosing scope or errors occur.
    persons.pop_back(); // If the db insertion fails, we should roll back.
  };
  // MAKE_SCOPE_EXIT(name) {action} - macro is used to create a new scope_exit object.
  scope_exit.dismiss(); // An exception was not thrown, so don't execute the scope_exit.
  ```

  ```cpp
  persons.push_back(person); // Add the person to db.

  auto scope_exit = make_scope_exit([]() { persons.pop_back(); });
  // make_scope_exit(A&& action) - function is used to create a new scope_exit object. It can be instantiated with a lambda function, a std::function<void()>, a functor, or a void(*)() function pointer.
  // ...
  scope_exit.dismiss(); // An exception was not thrown, so don't execute the scope_exit.
  ```

* With Scope Guard

  ```cpp
  std::fstream file("test.txt");
  WITH_SCOPE_EXIT({ file.close(); }) { // File closes when exit the enclosing with scope or errors occur.
    // ...
  };
  ```

## Synopsis

### Reference

#### scope_exit

* `scope_exit<F> make_scope_exit(F&& action);` - return scope_exit with the action.
* `SCOPE_EXIT{action};` - macro for creating scope_exit with the action.
* `MAKE_SCOPE_EXIT(name) {action};` - macro for creating named scope_exit with the action.
* `WITH_SCOPE_EXIT({action}) {/*...*/};` - macro for creating scope with scope_exit with the action.

#### scope_fail

* `scope_fail<F> make_scope_fail(F&& action);` - return scope_fail with the action.
* `SCOPE_FAIL{action};` - macro for creating scope_fail with the action.
* `MAKE_SCOPE_FAIL(name) {action};` - macro for creating named scope_fail with the action.
* `WITH_SCOPE_FAIL({action}) {/*...*/};` - macro for creating scope with scope_fail with the action.

#### scope_success

* `scope_success<F> make_scope_success(F&& action);` - return scope_success with the action.
* `SCOPE_SUCCESS{action};` - macro for creating scope_success with the action.
* `MAKE_SCOPE_SUCCESS(name) {action};` - macro for creating named scope_success with the action.
* `WITH_SCOPE_SUCCESS({action}) {/*...*/};` - macro for creating scope with scope_success with the action.

#### defer

* `DEFER{action};` - macro for creating defer with the action.
* `MAKE_DEFER(name) {action};` - macro for creating named defer with the action.
* `WITH_DEFER({action}) {/*...*/};` - macro for creating scope with defer with the action.

### Interface of scope_guard

scope_exit, scope_fail, scope_success implement scope_guard interface.

* `dismiss()` - dismiss executing action on scope exit.

#### Throwable settings

* `SCOPE_GUARD_NOTHROW_CONSTRUCTIBLE` define this to require nothrow constructible action.

* `SCOPE_GUARD_MAY_THROW_ACTION` define this to action may throw exceptions.

* `SCOPE_GUARD_NO_THROW_ACTION` define this to require noexcept action.

* `SCOPE_GUARD_SUPPRESS_THROW_ACTIONS` define this to exceptions during action will be suppressed.

* By default using `SCOPE_GUARD_MAY_THROW_ACTION`.

* `SCOPE_GUARD_CATCH_HANDLER` define this to add exceptions handler. If `SCOPE_GUARD_SUPPRESS_THROW_ACTIONS` is not defined, it will do nothing.

### Remarks

* If multiple Scope Guard statements appear in the same scope, the order they appear is the reverse of the order they are executed.

  ```cpp
  void f() {
    SCOPE_EXIT{ std::cout << "First" << std::endl; };
    SCOPE_EXIT{ std::cout << "Second" << std::endl; };
    SCOPE_EXIT{ std::cout << "Third" << std::endl; };
    ... // Other code.
    // Prints "Third".
    // Prints "Second".
    // Prints "First".
  }
  ```

## Integration

You should add required file [scope_guard.hpp](include/scope_guard.hpp).

## References

* [Andrei Alexandrescu "Systematic Error Handling in C++"](https://channel9.msdn.com/Shows/Going+Deep/C-and-Beyond-2012-Andrei-Alexandrescu-Systematic-Error-Handling-in-C)
* [Andrei Alexandrescu “Declarative Control Flow"](https://youtu.be/WjTrfoiB0MQ)

## Licensed under the [MIT License](LICENSE)
