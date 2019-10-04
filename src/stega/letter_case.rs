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
use crate::{BaconCodec, errors, Steganographer};

pub struct LetterCaseSteganographer {}

impl LetterCaseSteganographer {
    pub fn new() -> LetterCaseSteganographer {
        LetterCaseSteganographer {}
    }
}

impl Steganographer for LetterCaseSteganographer {
    type T = char;

    fn disguise<AB>(&self, secret: &[char], public: &[char], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=char>) -> errors::Result<Vec<char>> {
        let available_size = public.iter()
            .filter(|pc| pc.is_alphabetic())
            .count();
        let secret_size = secret.iter()
            .filter(|pc| pc.is_alphabetic())
            .count();

        if secret.iter()
            .filter(|s| !s.is_alphabetic() && s != &&' ')
            .count() > 0 {
            Err(errors::BaconError::SteganographerError(
                format!("The secret can contain only alphabetic characters. This is an invalid secret")))
        } else if available_size < secret_size * codec.encoded_group_size() {
            Err(errors::BaconError::SteganographerError(
                format!("The public input should have at least size {}. It was found to have {}",
                        secret_size * codec.encoded_group_size(),
                        available_size)))
        } else {
            let encoded = codec.encode(secret);

            let mut disguised: Vec<char> = Vec::new();
            let mut i = 0;

            for pc in public {
                if pc.is_alphabetic() {
                    let opt = encoded.get(i);
                    if opt.is_some() && codec.is_a(opt.unwrap()) {
                        let mut tmp: Vec<char> = pc.clone().to_lowercase().collect();
                        disguised.append(&mut tmp);
                        i = i + 1;
                    } else if opt.is_some() && codec.is_b(opt.unwrap()) {
                        let mut tmp: Vec<char> = pc.clone().to_uppercase().collect();
                        disguised.append(&mut tmp);
                        i = i + 1;
                    } else {
                        disguised.push(pc.clone())
                    }
                } else {
                    disguised.push(pc.clone())
                }
            }

            Ok(disguised)
        }
    }

    fn reveal<AB>(&self, input: &[char], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<char>> {
        let encoded: Vec<AB> = input.iter()
            .filter(|elem| elem.is_alphabetic())
            .map(|elem| {
                if elem.is_uppercase() {
                    codec.b()
                } else {
                    codec.a()
                }
            })
            .collect();
        Ok(codec.decode(&encoded))
    }
}

#[cfg(test)]
mod letter_case_tests {
    use std::iter::FromIterator;

    use crate::codecs::char_codec::CharCodec;

    use super::*;

    #[test]
    fn disguise_fails_because_of_public_message_length() {
        let codec = CharCodec::new('a', 'b');
        let s = LetterCaseSteganographer::new();
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &codec);
        assert!(output.is_err())
    }

    #[test]
    fn disguise_fails_because_of_no_alphabetic_secret() {
        let codec = CharCodec::new('a', 'b');
        let s = LetterCaseSteganographer::new();
        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', '1', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_err())
    }

    #[test]
    fn disguise_a_secret_to_a_char_array() {
        let codec = CharCodec::new('a', 'b');
        let s = LetterCaseSteganographer::new();
        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "tHiS IS a PUbLic mEssAge thaT cOntains A seCreT one");
    }

    #[test]
    fn reveal_a_secret_from_a_char_array() {
        let codec = CharCodec::new('a', 'b');
        let s = LetterCaseSteganographer::new();
        let public = "tHiS IS a PUbLic mEssAge thaT cOntains A seCreT one";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }
}
