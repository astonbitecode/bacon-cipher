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

## Quick example

```
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::BaconCodec;
use std::iter::FromIterator;

let codec = CharCodec::default();
let encoded = codec.encode(&['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']);
let string = String::from_iter(encoded.iter());

assert_eq!("ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA", string);
```
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
    fn disguise<AB>(&self, secret: &[Self::T], public: &[Self::T], codec: &BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<Self::T>>;

    /// Reveals the _secret_ that is hidden in an array of type `T`, using a [BaconCodec](trait.BaconCodec.html).
    fn reveal<AB>(&self, input: &[Self::T], codec: &BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<Self::T>>;
}
