[![crates.io](https://img.shields.io/crates/v/bacon-cipher.svg)](https://crates.io/crates/bacon-cipher)
[![Build Status](https://travis-ci.org/astonbitecode/bacon-cipher.svg?branch=master)](https://travis-ci.org/astonbitecode/bacon-cipher)
[![codecov](https://codecov.io/gh/astonbitecode/bacon-cipher/branch/master/graph/badge.svg)](https://codecov.io/gh/astonbitecode/bacon-cipher)

# bacon-cipher

An implementation of the [Bacon's cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher).

The crate offers codecs that _encode / decode_ and  steganographers that _hide / reveal_ encoded messages.

**Available codecs:**

* CharCodec: A codec that encodes data of type `char`.

    The encoding is done by substituting with two given elements (`elem_a` and `elem_b`) of type `T`.

    The substitution is done using the __first__ version of the Bacon's cipher.

* CharCodecV2: A codec that encodes data of type `char`.

    The encoding is done by substituting with two given elements (`elem_a` and `elem_b`) of type `T`.

    The substitution is done using the __second__ version of the Bacon's cipher.

**Available steganographers:**

* LetterCaseSteganographer: Applies steganography based on the case of the characters.

    E.g. Lowercase for Bacon's element A, capital for Bacon's element B.

* MarkdownSteganographer: Applies steganography based on Markdown tags that surround elements.

    E.g. Sourround an element with `**` for Bacon's element A and the rest of the elements are considered as Bacon's element B.

* SimpleTagSteganographer: Applies steganography based on HTML or XML tags that surround elements. (needs the feature `extended-steganography`)

    E.g. Sourround an element with `<b>` and `</b>` for Bacon's element A and with `<i>` and `</i>` for Bacon's element B.

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

### Letter case

#### Disguise a hidden message into a public one

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

#### Reveal a hidden message from a public one

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

### Markdown

#### Disguise a hidden message into a public one

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::stega::markdown::{MarkdownSteganographer, Marker};
use bacon_cipher::{BaconCodec, Steganographer};
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('a', 'b');

// Apply steganography based on Markdown markers
let s = MarkdownSteganographer::new(
    Marker::empty(),
    Marker::new(
        Some("*"),
        Some("*"))).unwrap();

// This is the public message in which we want to hide the secret one.
let public = "This is a public message that contains a secret one";

// This is the message that we want to hide.
let secret_chars: Vec<char> = "My secret".chars().collect();

let output = s.disguise(
    &secret_chars,
    &Vec::from_iter(public.chars()),
    &codec);
let string = String::from_iter(output.unwrap().iter());
assert!(string == "T*h*i*s* *is* a *pu*b*l*ic m*e*ss*a*ge tha*t* c*o*ntains *a* se*c*re*t* one");
```

#### Reveal a hidden message from a public one

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::stega::markdown::{MarkdownSteganographer, Marker};
use bacon_cipher::{BaconCodec, Steganographer};
use std::iter::FromIterator;

// Define a Bacon Codec that encodes using the characters 'A' and 'B'
let codec = CharCodec::new('a', 'b');

// Apply steganography based on Markdown markers
let s = MarkdownSteganographer::new(
    Marker::empty(),
    Marker::new(
        Some("*"),
        Some("*"))).unwrap();

// This is the public message that contains a hidden message
let public = "T*h*i*s* *is* a *pu*b*l*ic m*e*ss*a*ge tha*t* c*o*ntains *a* se*c*re*t* one";

// This is the hidden message
let output = s.reveal(
    &Vec::from_iter(public.chars()),
    &codec);
assert!(output.is_ok());
let string = String::from_iter(output.unwrap().iter());
assert!(string.starts_with("MYSECRET"));
```

## Licence

At your option, under:

* Apache License, Version 2.0, (http://www.apache.org/licenses/LICENSE-2.0)
* MIT license (http://opensource.org/licenses/MIT)
