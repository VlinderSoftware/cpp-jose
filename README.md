> [!WARNING]
> This code is in early development.
> The API needs work, testing has not been done beyond unit tests, etc.

# cpp-jose
JOSE implementation in modern C++

## Formatting

This repository uses `.clang-format` for C/C++ source formatting.

- PowerShell (format in place): `./Reformat.ps1`
- PowerShell (check only): `./Reformat.ps1 -CheckOnly`
- Bash (format in place): `./reformat.sh`
- Bash (check only): `./reformat.sh --check`

Both scripts format or check files under `src`, `include`, `tests`, and `examples`.
