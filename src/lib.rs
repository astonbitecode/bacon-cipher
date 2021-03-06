// Copyright 2019 astonbitecode
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
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

```
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

```
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

```
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

```
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

```
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

```
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

*/

pub mod codecs;
pub mod stega;
pub mod errors;

/// A codec that enables encoding and decoding based on the [Bacon's cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher)
pub trait BaconCodec {
    /// The type of the substitution characters A and B that produce a cipher output like ABABBBABBABAAABAABAAAAABABAAAAAABAABAABAABABBAABAABAAABBAAABAAAAAAABBAAABAA
    ///
    /// Can be char, bool or whatever
    type ABTYPE;
    /// The type of the content to be encoded to or decoded.
    type CONTENT;

    /// Encode an array of some type `Self::CONTENT`
    ///
    /// E.g. For `CONTENT=char`, `ABTYPE=char`, `a='A'` and `b='B'`, the encoding of `['M','y',' ','s','e','c','r','e','t']` is _ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA_
    fn encode(&self, input: &[Self::CONTENT]) -> Vec<Self::ABTYPE> {
        input.iter()
            .map(|elem| self.encode_elem(elem))
            .flat_map(|elem| elem)
            .collect()
    }

    /// Encodes a single emenent of `Self::CONTENT` to a Vec of `Self::ABTYPE`.
    fn encode_elem(&self, elem: &Self::CONTENT) -> Vec<Self::ABTYPE>;

    /// Decode an array of some type `Self::ABTYPE`.
    ///
    /// E.g. For `CONTENT=char`, `ABTYPE=char`, `a='A'` and `b='B'`, the decoding of _ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA_ is `['M','Y','S','E','C','R','E','T']`
    fn decode(&self, input: &[Self::ABTYPE]) -> Vec<Self::CONTENT> {
        input.chunks(self.encoded_group_size())
            .map(|elem| self.decode_elems(&elem))
            .collect()
    }

    /// Decode an array of elements to produce one element of `Self::CΟΝΤΕΝΤ`
    fn decode_elems(&self, elems: &[Self::ABTYPE]) -> Self::CONTENT;

    /// Returns the `A` substitution element.
    fn a(&self) -> Self::ABTYPE;

    /// Returns the `B` substitution element.
    fn b(&self) -> Self::ABTYPE;

    /// Returns the the size of the group of elements that represent a content encoding.
    ///
    /// E.g.: For the default Bacon's cipher, this is 5.
    fn encoded_group_size(&self) -> usize;

    /// Tests whether an element equals with the `A` substitution element.
    fn is_a(&self, elem: &Self::ABTYPE) -> bool;

    /// Tests whether an element equals with the `B` substitution element.
    fn is_b(&self, elem: &Self::ABTYPE) -> bool;
}

/// Transforms a given input of elements to / from a different form, based on a [BaconCodec](trait.BaconCodec.html).
pub trait Steganographer {
    /// The type of the elements to transform.
    type T;

    /// Encodes a _secret_ array of type `T`, using the a [BaconCodec](trait.BaconCodec.html) and applies the encoding
    /// by transforming a _public_ array of type `T` accordingly.
    ///
    /// The result is an array of type `T` that contains the hidden _secret_
    fn disguise<AB>(&self, secret: &[Self::T], public: &[Self::T], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<Self::T>>;

    /// Reveals the _secret_ that is hidden in an array of type `T`, using a [BaconCodec](trait.BaconCodec.html).
    fn reveal<AB>(&self, input: &[Self::T], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<Self::T>>;
}
