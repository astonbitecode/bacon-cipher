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
use crate::errors::BaconError;

#[derive(Debug, Clone, PartialEq)]
pub struct Marker {
    start_marker: Option<String>,
    end_marker: Option<String>,
}

impl Marker {
    pub fn new(start_marker: Option<&str>, end_marker: Option<&str>) -> Marker {
        Marker {
            start_marker: start_marker.map(|marker| marker.to_string()),
            end_marker: end_marker.map(|marker| marker.to_string()),
        }
    }

    pub fn empty() -> Marker {
        Marker {
            start_marker: None,
            end_marker: None,
        }
    }

    pub fn start_marker(&self) -> &Option<String> {
        &self.start_marker
    }

    pub fn end_marker(&self) -> &Option<String> {
        &self.end_marker
    }

    pub fn start_marker_string(&self) -> String {
        self.start_marker().clone().unwrap_or("".to_string())
    }

    pub fn end_marker_string(&self) -> String {
        self.end_marker().clone().unwrap_or("".to_string())
    }
}

pub struct MarkdownSteganographer {
    a_marker: Marker,
    b_marker: Marker,
}

impl MarkdownSteganographer {
    pub fn new(a_marker: Marker, b_marker: Marker) -> errors::Result<MarkdownSteganographer> {
        match (&a_marker.start_marker, &a_marker.end_marker, &b_marker.start_marker, &b_marker.end_marker) {
            (Some(asm), Some(aem), Some(bsm), Some(bem))
            if asm.contains(bsm) || asm.contains(bem) ||
                aem.contains(bsm) || aem.contains(bem) ||
                bsm.contains(asm) || bsm.contains(aem) ||
                bem.contains(asm) || bem.contains(aem) => {
                Err(BaconError::SteganographerError(format!("Cannot create a marker with {:?} and {:?}", a_marker, b_marker)))
            }
            _ => {
                Ok(MarkdownSteganographer {
                    a_marker,
                    b_marker,
                })
            }
        }
    }

    fn parse(&self, input: &str) -> Vec<ParsedInputElement> {
        let mut input = input;
        let mut input_elements: Vec<ParsedInputElement> = Vec::new();

        // Search for either a or b start marker
        while let Some((start_index, parsed_input_type)) = self
            // Get the start marker of A
            .a_marker.start_marker.as_ref()
            // Find the location of the start marker A
            .and_then(|a_start| input.find(a_start.as_str()))
            // Use the location in the loop and pass the parsed input type for A
            .and_then(|start_index| Some((start_index, ParsedInputType::A)))
            // If we have None from above, get the start marker of B
            .or(self.b_marker.start_marker.as_ref()
                .and_then(|b_start| input
                    // Find the location of the start marker B
                    .find(b_start.as_str())
                    // Use the location in the loop and pass the parsed input type for B
                    .and_then(|start_index| Some((start_index, ParsedInputType::B))))) {
            println!("=================");
            println!("input: {}", input);
            println!("start_index: {}", start_index);
            println!("parsed_input_type: {:?}", parsed_input_type);
            let start_size = match parsed_input_type {
                ParsedInputType::A => self.a_marker.start_marker.as_ref().unwrap().len(),
                ParsedInputType::B => self.b_marker.start_marker.as_ref().unwrap().len(),
                _ => 0,
            };
            let tmp: &str = &input[(start_index + start_size)..input.len()];
            println!("tmp: {}", tmp);
            let (end_opt, end_size) = match parsed_input_type {
                ParsedInputType::A => (self.a_marker.end_marker.as_ref(), self.a_marker.end_marker_string().len()),
                ParsedInputType::B => (self.b_marker.end_marker.as_ref(), self.b_marker.end_marker_string().len()),
                _ => (None, 0),
            };
            let end_index = (end_opt
                .and_then(|end| tmp.find(end.as_str()))
                .unwrap_or(tmp.len()) + start_size) + end_size;
            println!("end_index: {}", end_index);
            let input_element: &str = &input[(start_index + 1)..end_index];
            println!("input_element: {}", input_element);
            input_elements.push(ParsedInputElement::new(input_element.to_string(), parsed_input_type.clone()));
            if input.len() <= end_index {
                input = "";
            } else {
                input = &input[(end_index + end_size)..input.len()];
            }
        }
        println!("=================");
        input_elements
    }
}

impl Steganographer for MarkdownSteganographer {
    type T = char;

    fn disguise<AB>(&self, secret: &[char], public: &[char], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=char>) -> errors::Result<Vec<char>> {
        let encoded = codec.encode(secret);

        let mut disguised = String::new();
        let mut i = 0;

        for pc in public {
            if pc.is_alphabetic() {
                let opt = encoded.get(i);
                if opt.is_some() && codec.is_a(opt.unwrap()) {
                    disguised.push_str(&format!("{}{}{}",
                                                self.a_marker.start_marker_string(),
                                                pc.clone(),
                                                self.a_marker.end_marker_string()));
                    i = i + 1;
                } else if opt.is_some() && codec.is_b(opt.unwrap()) {
                    disguised.push_str(&format!("{}{}{}",
                                                self.b_marker.start_marker_string(),
                                                pc.clone(),
                                                self.b_marker.end_marker_string()));
                    i = i + 1;
                } else {
                    disguised.push(pc.clone())
                }
            } else {
                disguised.push(pc.clone())
            }
        }

        Ok(disguised
            .replace(&format!("{}{}", self.a_marker.end_marker_string(), self.a_marker.start_marker_string()), "")
            .replace(&format!("{}{}", self.b_marker.end_marker_string(), self.b_marker.start_marker_string()), "")
            .chars().collect())
    }

    fn reveal<AB>(&self, input: &[char], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<char>> {
//        let input_string = String::from_iter(input);
        unimplemented!();
//        let encoded: Vec<AB> = self.parse(&input_string).iter()
//            .map(|elem| {
//                if elem.tp == ParsedInputType::A {
//                    let v: Vec<AB> = elem.string.chars()
//                        .filter(|sc| sc.is_alphabetic())
//                        .map(|_| codec.a())
//                        .collect();
//                    v
//                } else {
//                    let v: Vec<AB> = elem.string.chars()
//                        .filter(|sc| sc.is_alphabetic())
//                        .map(|_| codec.b())
//                        .collect();
//                    v
//                }
//            })
//            .flat_map(|m| m)
//            .collect();
//        Ok(codec.decode(&encoded))
    }
}

#[derive(Debug, PartialEq)]
struct ParsedInputElement {
    string: String,
    tp: ParsedInputType,
}

impl ParsedInputElement {
    fn new(string: String, tp: ParsedInputType) -> ParsedInputElement {
        ParsedInputElement { string, tp }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum ParsedInputType {
    A,
    B,
    Other,
}

#[cfg(test)]
mod letter_case_tests {
    use std::iter::FromIterator;

    use crate::codecs::char_codec::CharCodec;

    use super::*;

    #[test]
    fn markers_creation() {
        let m1 = Marker::new(None, None);
        assert!(m1.start_marker() == &None);
        assert!(m1.end_marker() == &None);

        let m2 = Marker::new(Some("_"), Some("_"));
        assert!(m2.start_marker() == &Some("_".to_string()));
        assert!(m2.end_marker() == &Some("_".to_string()));

        let m3 = Marker::empty();
        assert!(m3.start_marker() == &None);
        assert!(m3.end_marker() == &None);
    }

    #[test]
    fn markers_to_string() {
        let m = Marker::new(Some("__"), Some("__"));
        assert!(m.start_marker_string() == ("__"));
        assert!(m.end_marker_string() == ("__"));
    }

    #[test]
    fn steganographer_creation_failure() {
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("*"),
                Some("*")),
            Marker::new(
                Some("**"),
                Some("**")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("*"),
                Some("!")),
            Marker::new(
                Some("@"),
                Some("**")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("!"),
                Some("*")),
            Marker::new(
                Some("**"),
                Some("@")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::new(
                Some("*"),
                Some("*")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("@")),
            Marker::new(
                Some("*"),
                Some("!")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("@"),
                Some("**")),
            Marker::new(
                Some("!"),
                Some("*")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::new(
                Some("**"),
                Some("**")));
        assert!(res.is_err());
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_b_marker() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::empty(),
            Marker::new(
                Some("*"),
                Some("*"))).unwrap();

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "T*h*i*s* *is* a *pu*b*l*ic m*e*ss*a*ge tha*t* c*o*ntains *a* se*c*re*t* one");
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_a_tag() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::empty()).unwrap();

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "**T**h**i**s is **a** pu**b**l**ic** **m**e**ss**a**ge** **tha**t **c**o**ntains** a **se**c**re**t **o**ne");
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_a_b_tags() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::new(
                Some("*"),
                Some("*")),
            Marker::new(
                Some("!"),
                Some("!"))).unwrap();

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "*T*!h!*i*!s! !is! *a* !pu!*b*!l!*ic* *m*!e!*ss*!a!*ge* *tha*!t! *c*!o!*ntains* !a! *se*!c!*re*!t! *o*ne");
    }

    #[test]
    #[ignore]
    fn parse() {
        let masked = "!T!*h*!i!*s* *is* !a! *pu*!b!*l*!ic m!*e*!ss!*a*!ge tha!*t*! c!*o*!ntains !*a*! se!*c*!re!*t*! one!";

        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::new(
                Some("*"),
                Some("*")),
            Marker::new(
                Some("!"),
                Some("!")))
            .unwrap();

        println!("----------------------------------{:?}", s.parse(masked));
    }
}