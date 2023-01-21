# CTHASH (Compile Time Hash)

This library is constexpr implementation of SHA-2 family of hashes.

## Supported hash function

The library also implements hash_value literals in namespace `cthash::literals` (suffixes in parenthesis for each hash function type).

* SHA-224 (`_sha224`)
* SHA-256 (`_sha256`)
* SHA-384 (`_sha384`)
* SHA-512 (`_sha512`)
* SHA-512/t (only for T dividable by 8) (`_sha512_224`, `_sha512_256`)

## Example

```c++
using namespace cthash::literals;

constexpr auto my_hash = cthash::sha256{}.update("hello there!").final();
// or
constexpr auto my_hash = cthash::simple<cthash::sha256>("hello there!");

static_assert(my_hash == "c69509590d81db2f37f9d75480c8efedf79a77933db5a8319e52e13bfd9874a3"_sha256);
```

### Including library

You can include specific hash function only by `#include <cthash/variants/sha256.hpp>` or you can include whole library by `#include <cthash/cthash.hpp>`

#### Specific include for SHA-512/t

Just include `#include <cthash/variants/sha512/t.hpp>`.

## Implementation note

There is no allocation at all, everything is done as a value type from user's perspective. No explicit optimizations were done (for now).
