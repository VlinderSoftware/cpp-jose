# C++ Coding Style Guide

- **Standards:** Use C++20 or C++23 standards.
- **Formatting:** Use 4 spaces for indentation, braces on new lines (Allman style), and `clang-format` if available.
- **Naming:**
    - Types/Classes: `PascalCase`
    - Functions: `camelCase`
    - Variables: `snake_case`
    - Private members: `suffix_snake_case_`
- **Modern C++:**
    - Use `auto` for type deduction when readable.
    - Use `nullptr` instead of `NULL` or `0`.
    - Use range-based for loops.
    - Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) instead of `new`/`delete`.
    - Use `std::string` and `std::vector` instead of C-style arrays.
- **Structure:**
    - Use `#pragma once` for header guards.
    - Organize headers: C++ Standard Library, Third-party, Project headers.
- **Comments:** Use `///` for documentation comments to enable Doxygen formatting.
