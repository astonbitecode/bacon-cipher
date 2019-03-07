[![crates.io](https://img.shields.io/crates/v/bacon-cipher.svg)](https://crates.io/crates/bacon-cipher)
[![Build Status](https://travis-ci.org/astonbitecode/bacon-cipher.svg?branch=master)](https://travis-ci.org/astonbitecode/bacon-cipher)
[![codecov](https://codecov.io/gh/astonbitecode/bacon-cipher/branch/master/graph/badge.svg)](https://codecov.io/gh/astonbitecode/bacon-cipher)

# bacon-cipher

An implementation of the [Bacon's cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher).

The crate offers codecs that _encode / decode_ and  steganographers that _hide / reveal_ encoded messages

## Encoding - Decoding

### Encode a message to Bacon codes

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::BaconCodec;
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('A', 'B');

// This is the secret to encode
let secret: Vec<char> = "My secret".chars().collect();

// Get the encoded chars
let encoded_chars = codec.encode(&secret);
let encoded_string = String::from_iter(encoded_chars.iter());

assert_eq!("ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA", encoded_string);
```

### Decode Bacon codes

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::BaconCodec;
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('A', 'B');

// These are the encoded characters
let encoded_chars: Vec<char> = "ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA".chars().collect();

// Retrieve the decoded chars
let decoded = codec.decode(&encoded_chars);
let string = String::from_iter(decoded.iter());

assert_eq!("MYSECRET", string);
```

## Steganography

### Disguise a hidden message into a public one

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::stega::letter_case::LetterCaseSteganographer;
use bacon_cipher::{BaconCodec, Steganographer};
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('a', 'b');

// Apply steganography based on the case of the characters
let s = LetterCaseSteganographer::new();

// This is the public message in which we want to hide the secret one.
let public_chars: Vec<char> = "This is a public message that contains a secret one".chars().collect();

// This is the message that we want to hide.
let secret_chars: Vec<char> = "My secret".chars().collect();

// This is the public message that contains the secret one
let disguised_public = s.disguise(&secret_chars, &public_chars, &codec);
let string = String::from_iter(disguised_public.unwrap().iter());

assert!(string == "tHiS IS a PUbLic mEssAge thaT cOntains A seCreT one");
```

### Reveal a hidden message from a public one

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::stega::letter_case::LetterCaseSteganographer;
use bacon_cipher::{BaconCodec, Steganographer};
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('a', 'b');

// Apply steganography based on the case of the characters
let s = LetterCaseSteganographer::new();

// This is the public message that contains a hidden message
let public_chars: Vec<char> = "tHiS IS a PUbLic mEssAge thaT cOntains A seCreT one".chars().collect();

// This is the hidden message
let output = s.reveal(&public_chars, &codec);
let hidden_message = String::from_iter(output.unwrap().iter());
assert!(hidden_message.starts_with("MYSECRET"));

```

## Licence

At your option, under: 

* Apache License, Version 2.0, (http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (http://opensource.org/licenses/MIT)