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
use std::marker::PhantomData;

use crate::BaconCodec;

#[derive(PartialEq, Clone)]
/// A codec that encodes data of type `char`.
///
/// The encoding is done by substituting with two given elements (`elem_a` and `elem_b`) of type `T`.
///
/// The substitution is done using the __first__ version of the Bacon's cipher.
pub struct CharCodec<T> {
    pd: PhantomData<char>,
    elem_a: T,
    elem_b: T,
}

impl<T> CharCodec<T> {
    /// Create a new `CharCodec` using elements `elem_a` and `elem_b` for substitution.
    pub fn new(elem_a: T, elem_b: T) -> CharCodec<T> {
        CharCodec { pd: PhantomData, elem_a, elem_b }
    }
}

impl Default for CharCodec<char> {
    /// A `CharCodec` with `CONTENT=char`, `A='A'` and `B='B'`
    ///
    /// It encodes the following secret:
    /// `['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']` is
    ///
    /// To:
    /// ['a', 'b', 'a', 'b', 'b', 'b', 'a', 'b', 'b', 'a', 'b', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'b', 'a']
    fn default() -> CharCodec<char> {
        CharCodec::new('A', 'B')
    }
}

impl<T: PartialEq + Clone> BaconCodec for CharCodec<T> {
    type ABTYPE = T;
    type CONTENT = char;

    fn encode_elem(&self, elem: &char) -> Vec<T> {
        match elem {
            'a' | 'A' => vec![self.a(), self.a(), self.a(), self.a(), self.a()],
            'b' | 'B' => vec![self.a(), self.a(), self.a(), self.a(), self.b()],
            'c' | 'C' => vec![self.a(), self.a(), self.a(), self.b(), self.a()],
            'd' | 'D' => vec![self.a(), self.a(), self.a(), self.b(), self.b()],
            'e' | 'E' => vec![self.a(), self.a(), self.b(), self.a(), self.a()],
            'f' | 'F' => vec![self.a(), self.a(), self.b(), self.a(), self.b()],
            'g' | 'G' => vec![self.a(), self.a(), self.b(), self.b(), self.a()],
            'h' | 'H' => vec![self.a(), self.a(), self.b(), self.b(), self.b()],
            'i' | 'I' => vec![self.a(), self.b(), self.a(), self.a(), self.a()],
            'j' | 'J' => vec![self.a(), self.b(), self.a(), self.a(), self.a()],
            'k' | 'K' => vec![self.a(), self.b(), self.a(), self.a(), self.b()],
            'l' | 'L' => vec![self.a(), self.b(), self.a(), self.b(), self.a()],
            'm' | 'M' => vec![self.a(), self.b(), self.a(), self.b(), self.b()],
            'n' | 'N' => vec![self.a(), self.b(), self.b(), self.a(), self.a()],
            'o' | 'O' => vec![self.a(), self.b(), self.b(), self.a(), self.b()],
            'p' | 'P' => vec![self.a(), self.b(), self.b(), self.b(), self.a()],
            'q' | 'Q' => vec![self.a(), self.b(), self.b(), self.b(), self.b()],
            'r' | 'R' => vec![self.b(), self.a(), self.a(), self.a(), self.a()],
            's' | 'S' => vec![self.b(), self.a(), self.a(), self.a(), self.b()],
            't' | 'T' => vec![self.b(), self.a(), self.a(), self.b(), self.a()],
            'u' | 'U' => vec![self.b(), self.a(), self.a(), self.b(), self.b()],
            'v' | 'V' => vec![self.b(), self.a(), self.a(), self.b(), self.b()],
            'w' | 'W' => vec![self.b(), self.a(), self.b(), self.a(), self.a()],
            'x' | 'X' => vec![self.b(), self.a(), self.b(), self.a(), self.b()],
            'y' | 'Y' => vec![self.b(), self.a(), self.b(), self.b(), self.a()],
            'z' | 'Z' => vec![self.b(), self.a(), self.b(), self.b(), self.b()],
            _ => vec![]
        }
    }

    fn decode_elems(&self, elems: &[T]) -> char {
        match elems {
            m if m == vec![self.a(), self.a(), self.a(), self.a(), self.a()].as_slice() => 'A',
            m if m == vec![self.a(), self.a(), self.a(), self.a(), self.b()].as_slice() => 'B',
            m if m == vec![self.a(), self.a(), self.a(), self.b(), self.a()].as_slice() => 'C',
            m if m == vec![self.a(), self.a(), self.a(), self.b(), self.b()].as_slice() => 'D',
            m if m == vec![self.a(), self.a(), self.b(), self.a(), self.a()].as_slice() => 'E',
            m if m == vec![self.a(), self.a(), self.b(), self.a(), self.b()].as_slice() => 'F',
            m if m == vec![self.a(), self.a(), self.b(), self.b(), self.a()].as_slice() => 'G',
            m if m == vec![self.a(), self.a(), self.b(), self.b(), self.b()].as_slice() => 'H',
            m if m == vec![self.a(), self.b(), self.a(), self.a(), self.a()].as_slice() => 'I',
            m if m == vec![self.a(), self.b(), self.a(), self.a(), self.a()].as_slice() => 'J',
            m if m == vec![self.a(), self.b(), self.a(), self.a(), self.b()].as_slice() => 'K',
            m if m == vec![self.a(), self.b(), self.a(), self.b(), self.a()].as_slice() => 'L',
            m if m == vec![self.a(), self.b(), self.a(), self.b(), self.b()].as_slice() => 'M',
            m if m == vec![self.a(), self.b(), self.b(), self.a(), self.a()].as_slice() => 'N',
            m if m == vec![self.a(), self.b(), self.b(), self.a(), self.b()].as_slice() => 'O',
            m if m == vec![self.a(), self.b(), self.b(), self.b(), self.a()].as_slice() => 'P',
            m if m == vec![self.a(), self.b(), self.b(), self.b(), self.b()].as_slice() => 'Q',
            m if m == vec![self.b(), self.a(), self.a(), self.a(), self.a()].as_slice() => 'R',
            m if m == vec![self.b(), self.a(), self.a(), self.a(), self.b()].as_slice() => 'S',
            m if m == vec![self.b(), self.a(), self.a(), self.b(), self.a()].as_slice() => 'T',
            m if m == vec![self.b(), self.a(), self.a(), self.b(), self.b()].as_slice() => 'U',
            m if m == vec![self.b(), self.a(), self.a(), self.b(), self.b()].as_slice() => 'V',
            m if m == vec![self.b(), self.a(), self.b(), self.a(), self.a()].as_slice() => 'W',
            m if m == vec![self.b(), self.a(), self.b(), self.a(), self.b()].as_slice() => 'X',
            m if m == vec![self.b(), self.a(), self.b(), self.b(), self.a()].as_slice() => 'Y',
            m if m == vec![self.b(), self.a(), self.b(), self.b(), self.b()].as_slice() => 'Z',
            _ => ' '
        }
    }

    fn a(&self) -> T { self.elem_a.clone() }

    fn b(&self) -> T { self.elem_b.clone() }

    fn encoded_group_size(&self) -> usize { 5 }

    fn is_a(&self, elem: &T) -> bool {
        elem == &self.a()
    }

    fn is_b(&self, elem: &T) -> bool {
        elem == &self.b()
    }
}

// ---------------------------------------------- V2 ---------------------------------------------//

#[derive(PartialEq, Clone)]
/// A codec that encodes data of type `char`.
///
/// The encoding is done by substituting with two given elements (`elem_a` and `elem_b`) of type `T`.
///
/// The substitution is done using the __second__ version of the Bacon's cipher.
pub struct CharCodecV2<T> {
    pd: PhantomData<char>,
    elem_a: T,
    elem_b: T,
}

impl<T> CharCodecV2<T> {
    /// Create a new `CharCodec` using elements `elem_a` and `elem_b` for substitution.
    pub fn new(elem_a: T, elem_b: T) -> CharCodecV2<T> {
        CharCodecV2 { pd: PhantomData, elem_a, elem_b }
    }
}

impl Default for CharCodecV2<char> {
    /// A `CharCodec` with `CONTENT=char`, `A='A'` and `B='B'`
    ///
    /// It encodes the following secret:
    /// `['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']` is
    ///
    /// To:
    /// ['a', 'b', 'a', 'b', 'b', 'b', 'a', 'b', 'b', 'a', 'b', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'b', 'a']
    fn default() -> CharCodecV2<char> {
        CharCodecV2::new('A', 'B')
    }
}

impl<T: PartialEq + Clone> BaconCodec for CharCodecV2<T> {
    type ABTYPE = T;
    type CONTENT = char;

    fn encode_elem(&self, elem: &char) -> Vec<T> {
        match elem {
            'a' | 'A' => vec![self.a(), self.a(), self.a(), self.a(), self.a()],
            'b' | 'B' => vec![self.a(), self.a(), self.a(), self.a(), self.b()],
            'c' | 'C' => vec![self.a(), self.a(), self.a(), self.b(), self.a()],
            'd' | 'D' => vec![self.a(), self.a(), self.a(), self.b(), self.b()],
            'e' | 'E' => vec![self.a(), self.a(), self.b(), self.a(), self.a()],
            'f' | 'F' => vec![self.a(), self.a(), self.b(), self.a(), self.b()],
            'g' | 'G' => vec![self.a(), self.a(), self.b(), self.b(), self.a()],
            'h' | 'H' => vec![self.a(), self.a(), self.b(), self.b(), self.b()],
            'i' | 'I' => vec![self.a(), self.b(), self.a(), self.a(), self.a()],
            'j' | 'J' => vec![self.a(), self.b(), self.a(), self.a(), self.b()],
            'k' | 'K' => vec![self.a(), self.b(), self.a(), self.b(), self.a()],
            'l' | 'L' => vec![self.a(), self.b(), self.a(), self.b(), self.b()],
            'm' | 'M' => vec![self.a(), self.b(), self.b(), self.a(), self.a()],
            'n' | 'N' => vec![self.a(), self.b(), self.b(), self.a(), self.b()],
            'o' | 'O' => vec![self.a(), self.b(), self.b(), self.b(), self.a()],
            'p' | 'P' => vec![self.a(), self.b(), self.b(), self.b(), self.b()],
            'q' | 'Q' => vec![self.b(), self.a(), self.a(), self.a(), self.a()],
            'r' | 'R' => vec![self.b(), self.a(), self.a(), self.a(), self.b()],
            's' | 'S' => vec![self.b(), self.a(), self.a(), self.b(), self.a()],
            't' | 'T' => vec![self.b(), self.a(), self.a(), self.b(), self.b()],
            'u' | 'U' => vec![self.b(), self.a(), self.b(), self.a(), self.a()],
            'v' | 'V' => vec![self.b(), self.a(), self.b(), self.a(), self.b()],
            'w' | 'W' => vec![self.b(), self.a(), self.b(), self.b(), self.a()],
            'x' | 'X' => vec![self.b(), self.a(), self.b(), self.b(), self.b()],
            'y' | 'Y' => vec![self.b(), self.b(), self.a(), self.a(), self.a()],
            'z' | 'Z' => vec![self.b(), self.b(), self.a(), self.a(), self.b()],
            _ => vec![]
        }
    }

    fn decode_elems(&self, elems: &[T]) -> char {
        match elems {
            m if m == vec![self.a(), self.a(), self.a(), self.a(), self.a()].as_slice() => 'A',
            m if m == vec![self.a(), self.a(), self.a(), self.a(), self.b()].as_slice() => 'B',
            m if m == vec![self.a(), self.a(), self.a(), self.b(), self.a()].as_slice() => 'C',
            m if m == vec![self.a(), self.a(), self.a(), self.b(), self.b()].as_slice() => 'D',
            m if m == vec![self.a(), self.a(), self.b(), self.a(), self.a()].as_slice() => 'E',
            m if m == vec![self.a(), self.a(), self.b(), self.a(), self.b()].as_slice() => 'F',
            m if m == vec![self.a(), self.a(), self.b(), self.b(), self.a()].as_slice() => 'G',
            m if m == vec![self.a(), self.a(), self.b(), self.b(), self.b()].as_slice() => 'H',
            m if m == vec![self.a(), self.b(), self.a(), self.a(), self.a()].as_slice() => 'I',
            m if m == vec![self.a(), self.b(), self.a(), self.a(), self.b()].as_slice() => 'J',
            m if m == vec![self.a(), self.b(), self.a(), self.b(), self.a()].as_slice() => 'K',
            m if m == vec![self.a(), self.b(), self.a(), self.b(), self.b()].as_slice() => 'L',
            m if m == vec![self.a(), self.b(), self.b(), self.a(), self.a()].as_slice() => 'M',
            m if m == vec![self.a(), self.b(), self.b(), self.a(), self.b()].as_slice() => 'N',
            m if m == vec![self.a(), self.b(), self.b(), self.b(), self.a()].as_slice() => 'O',
            m if m == vec![self.a(), self.b(), self.b(), self.b(), self.b()].as_slice() => 'P',
            m if m == vec![self.b(), self.a(), self.a(), self.a(), self.a()].as_slice() => 'Q',
            m if m == vec![self.b(), self.a(), self.a(), self.a(), self.b()].as_slice() => 'R',
            m if m == vec![self.b(), self.a(), self.a(), self.b(), self.a()].as_slice() => 'S',
            m if m == vec![self.b(), self.a(), self.a(), self.b(), self.b()].as_slice() => 'T',
            m if m == vec![self.b(), self.a(), self.b(), self.a(), self.a()].as_slice() => 'U',
            m if m == vec![self.b(), self.a(), self.b(), self.a(), self.b()].as_slice() => 'V',
            m if m == vec![self.b(), self.a(), self.b(), self.b(), self.a()].as_slice() => 'W',
            m if m == vec![self.b(), self.a(), self.b(), self.b(), self.b()].as_slice() => 'X',
            m if m == vec![self.b(), self.b(), self.a(), self.a(), self.a()].as_slice() => 'Y',
            m if m == vec![self.b(), self.b(), self.a(), self.a(), self.b()].as_slice() => 'Z',
            _ => ' '
        }
    }

    fn a(&self) -> T { self.elem_a.clone() }

    fn b(&self) -> T { self.elem_b.clone() }

    fn encoded_group_size(&self) -> usize { 5 }

    fn is_a(&self, elem: &T) -> bool {
        elem == &self.a()
    }

    fn is_b(&self, elem: &T) -> bool {
        elem == &self.b()
    }
}

#[cfg(test)]
mod char_codec_tests {
    use std::iter::FromIterator;

    use super::*;

    #[test]
    fn encode_chars_to_cipher_of_chars() {
        let codec = CharCodec::new('a', 'b');
        let encoded = codec.encode(&['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']);
        let string = String::from_iter(encoded.iter());
        assert_eq!("ababbbabbabaaabaabaaaaababaaaaaabaabaaba", string);
    }

    #[test]
    fn encode_all_chars_to_cipher_of_chars() {
        let codec = CharCodec::new('a', 'b');
        let encoded = codec.encode(&['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']);
        let string = String::from_iter(encoded.iter());
        assert_eq!("aaaaaaaaabaaabaaaabbaabaaaababaabbaaabbbabaaaabaaaabaabababaababbabbaaabbababbbaabbbbbaaaabaaabbaababaabbbaabbbabaabababbabbababbb", string);
    }

    #[test]
    fn encode_all_chars_to_cipher_of_chars_v2() {
        let codec = CharCodecV2::new('a', 'b');
        let encoded = codec.encode(&['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']);
        let string = String::from_iter(encoded.iter());
        assert_eq!("aaaaaaaaabaaabaaaabbaabaaaababaabbaaabbbabaaaabaabababaababbabbaaabbababbbaabbbbbaaaabaaabbaababaabbbabaabababbabbababbbbbaaabbaab", string);
    }

    #[test]
    fn encode_all_capital_chars_to_cipher_of_chars() {
        let codec = CharCodec::new('a', 'b');
        let encoded = codec.encode(&['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']);
        let string = String::from_iter(encoded.iter());
        assert_eq!("aaaaaaaaabaaabaaaabbaabaaaababaabbaaabbbabaaaabaaaabaabababaababbabbaaabbababbbaabbbbbaaaabaaabbaababaabbbaabbbabaabababbabbababbb", string);
    }

    #[test]
    fn encode_all_capital_chars_to_cipher_of_chars_v2() {
        let codec = CharCodecV2::new('a', 'b');
        let encoded = codec.encode(&['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']);
        let string = String::from_iter(encoded.iter());
        assert_eq!("aaaaaaaaabaaabaaaabbaabaaaababaabbaaabbbabaaaabaabababaababbabbaaabbababbbaabbbbbaaaabaaabbaababaabbbabaabababbabbababbbbbaaabbaab", string);
    }

    #[test]
    fn decode_cipher_of_chars_to_chars() {
        let codec = CharCodec::new('a', 'b');
        let decoded = codec.decode(&['a', 'b', 'a', 'b', 'b', 'b', 'a', 'b', 'b', 'a', 'b', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'b', 'a', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'a', 'b', 'a']);
        let string = String::from_iter(decoded.iter());
        assert_eq!("MYSECRET", string);
    }

    #[test]
    fn decode_cipher_of_all_chars_to_chars() {
        let codec = CharCodec::new('a', 'b');
        let decoded = codec.decode(&['a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'a',
            'b', 'b', 'a', 'a', 'b', 'a', 'a', 'a', 'a', 'b', 'a', 'b', 'a', 'a', 'b', 'b', 'a', 'a', 'a', 'b', 'b', 'b', 'a', 'b', 'a', 'a', 'a', 'a',
            'b', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'b', 'a', 'b', 'a', 'b', 'a', 'a', 'b', 'a', 'b', 'b', 'a', 'b', 'b', 'a', 'a', 'a', 'b', 'b', 'a',
            'b', 'a', 'b', 'b', 'b', 'a', 'a', 'b', 'b', 'b', 'b', 'b', 'a', 'a', 'a', 'a', 'b', 'a', 'a', 'a', 'b', 'b', 'a', 'a', 'b', 'a', 'b', 'a',
            'a', 'b', 'b', 'b', 'a', 'a', 'b', 'b', 'b', 'a', 'b', 'a', 'a', 'b', 'a', 'b', 'a', 'b', 'b', 'a', 'b', 'b', 'a', 'b', 'a', 'b', 'b', 'b']);
        let string = String::from_iter(decoded.iter());
        assert_eq!("ABCDEFGHIIKLMNOPQRSTUUWXYZ", string);
    }

    #[test]
    fn encode_chars_to_cipher_of_bools() {
        let codec = CharCodec::new(false, true);
        let encoded = codec.encode(&['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']);
        assert_eq!(vec![false, true, false, true, true, true, false, true, true, false, true, false, false, false, true, false, false, true, false, false, false, false, false, true, false, true, false, false, false, false, false, false, true, false, false, true, false, false, true, false], encoded);
    }

    #[test]
    fn decode_cipher_of_bools_to_chars() {
        let codec = CharCodec::new(false, true);
        let decoded = codec.decode(&vec![false, true, false, true, true, true, false, true, true, false, true, false, false, false, true, false, false, true, false, false, false, false, false, true, false, true, false, false, false, false, false, false, true, false, false, true, false, false, true, false]);
        let string = String::from_iter(decoded.iter());
        assert_eq!("MYSECRET", string);
    }
}
