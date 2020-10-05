# x64

x64 assembler library in C.

# About

The goal is to be able to comfortably generate x64 native code to memory and then run it. Useful for runtime code generation, compilers, code optimizations.

Made as part of learning how x64 encoding works. Library is set out to produce same code as `ML64` currently, since it's the assembler used for generating tests. The `GCC` one does prefer slightly different variants of some byte encodings. I'm trying to keep track of these so I will be able to generate tests from `GCC` too.

# x64 instructions

- `mov`
- `add`
- `sub`
- `and`
- `or`
- `xor`
- `push`
- `pop`
- `ret`

Features:

- All `reg/mem`, `mem/reg`, `mem/i` and `reg/i` supported.
- `REX` prefix generated only when needed.
- Absolute addressing mode supported.
- Relative addressing mode supported.
- `RBP` indexing supported.
- GCC-style `RSP` indexing supported (as long as scale is 1).
- Always choosing the shortest byte sequence as long as the result is the same. (This will need some more testing, though.)

Missing:

- Opcodes working just with `RAX` with `reg/*` not supported yet.

# Usage

**Still under development with some major changes pending.** Released out for people to use it early should they need it. Library is developed in my private repository and each major change is pushed here. I'll eventually move to this repo for further development.

```c
// Binary
X64Inst x64_mov(X64Size size, X64Operand D, X64Operand S);
X64Inst x64_add(X64Size size, X64Operand D, X64Operand S);
X64Inst x64_sub(X64Size size, X64Operand D, X64Operand S);
X64Inst x64_and(X64Size size, X64Operand D, X64Operand S);
X64Inst x64_or (X64Size size, X64Operand D, X64Operand S);
X64Inst x64_xor(X64Size size, X64Operand D, X64Operand S);

// Unary
X64Inst x64_pop(X64Operand S);
X64Inst x64_push(X64Operand S);

// Nullary
X64Inst x64_ret();
```

Functions return `X64Inst` structure, which is just a static buffer with `.bytes` and `.count`. The structure also contains `.error` string which is set in case there was an error processing. This behavior will eventually change to a proper buffered writer and custom error handler.

Where `X64Size size` denotes intent of size on the operation. In case it is not possible to satisfy the size and operands for given instruction, error is returned via `XInst.error`.

```c
enum X64Size {
    X64_S8
    X64_S16
    X64_S32
    X64_S64
};
```

`X64Operand` can be constructed either directly or via three helper functions:

- Register operand:
  - `X64Operand x64r(X64Reg reg)`
- Memory expression operand:
  - `X64Operand x64m(X64Reg base, X64Reg index, X64Scale scale, uint64_t displacement)`
- Immediate (constant) operand:
  - `X64Operand x64i(uint64_t imm)`

# TODO

- Obviously more instructions.
  - Priority on instructions that map to C-like language expressions (arithmetics, calls)
  - Floating point (via SSE+).
  - Vector operations.
- Some API changes regarding how `size` argument is used.
- Use proper buffer writer with user callback.
- Use user callback for error handling.

# Testing

There's a test generator for all of the instruction with all happy-path possibilities. Additionally I'm adding test for error cases. The tests are not yet part of the release, but will be pushed out soon.

Tests are working as follows:

1. First we generate all permutations of all valid arguments.
2. Then we generate and assembly file with corresponding `ML64` notation.
3. The assembly file is passed through `ML64` assembler that produces `OBJ` file.
4. `OBJ` file is disassembled through `DUMPBIN` and we extract bytes for each instruction.
5. We generate a C source file with each permutation mapped to it's expected result bytes from `DUMPBIN`.
6. We compare result from the library to result from `ML64`.

Tests coverage per instruction:

```
 mov 7510 tests
 sub 7508 tests
 add 7508 tests
 and 7508 tests
  or 7508 tests
 xor 7508 tests
 pop  442 tests
push  445 tests
```

# Links

- [x64 encoding writeup](https://github.com/martincohen/Wiki/wiki/x64)
  - Not comprehensive yet, but can help with additional instructions should one need them.
- [Development streams](https://twitch.tv/martincohen)
  - Occasional streams.
- [Development streams archive on YouTube](https://www.youtube.com/playlist?list=PLPdqby1EYYdUJw27y0LpIffko8EhP6ICs)
  - Kept in sync with archive on Twitch.
