## Introduction 
Solutions to the [Cryptopals](https://cryptopals.com/) challenges, sets 1 through 6, in Rust. These solutions were written with the explicit purpose of learning Rust, so don't expect the most beautiful or performant code.

## Usage
If you are adventurous, you can compile & test the solutions using the `cargo test` command. This command may take a reasonably long time (~10 minutes).

## Solutions
* [Set 1](src/set1/mod.rs)
* [Set 2](src/set2/mod.rs)
* [Set 3](src/set3/mod.rs)
* [Set 4](src/set4/mod.rs)
* [Set 5](src/set5/mod.rs)
* [Set 6](src/set6/mod.rs)

## Shared
Some other code includes pure Rust implementations of [MD-4](src/shared/md4.rs), the [Mersenne Twister](src/shared/mersenne_twister.rs), [SHA-1](src/shared/sha1.rs), and [SHA-256](src/shared/sha256.rs). Obviously, this code should never be used in real-world applications, but it at least looks like it produces the correct values.
