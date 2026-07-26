> [!WARNING]
> This code is in early development.
> The API needs work, testing has not been done beyond unit tests, etc.

# cpp-jose
JOSE implementation in modern C++

## Interoperability notes

### JWE JSON: `alg` and `enc` are read only from the protected header

When parsing the JWE JSON serialisations (RFC 7516 §7.2), this library resolves
the key-encryption algorithm (`alg`) and the content-encryption algorithm (`enc`)
**exclusively from the JWE Protected Header** — the only header covered by the
AAD. Two kinds of token that RFC 7516 permits are therefore rejected:

- **`alg` absent from the protected header.** RFC 7516 §7.2.1 allows `alg` to be
  carried in the shared unprotected header or in a per-recipient header. Such a
  token is rejected rather than parsed.
- **Recipients selecting different algorithms.** A per-recipient `header` may
  repeat `alg`/`enc`, but only with values equal to the protected header's. A
  token whose recipients use *different* key-encryption algorithms — such as the
  multiple-recipient example in RFC 7520 §5.13 — is rejected.

This is deliberate. The shared unprotected and per-recipient headers are not
integrity-protected, so honouring an algorithm from them would let an attacker
substitute a weaker one (for example downgrading `RSA-OAEP` to `RSA1_5`, which
exposes a padding oracle) without invalidating the token.

What still works:

- Tokens produced by this library always carry `alg` and `enc` in the protected
  header, so they round-trip regardless of serialisation.
- Multiple recipients are supported when they share one key-encryption algorithm.
- Per-recipient headers remain useful for key identification (`kid`) and for the
  parameters RFC 7518 requires there: `epk` for ECDH-ES (§4.6) and `iv`/`tag` for
  AES-GCM key wrapping (§4.7).

Lifting the first restriction requires parsing the shared unprotected header; see
`TODO.txt` for the deferred work.

## Formatting

This repository uses `.clang-format` for C/C++ source formatting.

- PowerShell (format in place): `./Reformat.ps1`
- PowerShell (check only): `./Reformat.ps1 -CheckOnly`
- Bash (format in place): `./reformat.sh`
- Bash (check only): `./reformat.sh --check`

Both scripts format or check files under `src`, `include`, `tests`, and `examples`.
