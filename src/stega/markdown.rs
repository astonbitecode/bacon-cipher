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

use std::iter::FromIterator;

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

    pub fn is_empty(&self) -> bool {
        self == &Self::empty()
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
            (None, None, None, None) => {
                Err(BaconError::SteganographerError(format!("Cannot create a marker with both A and B undefined")))
            }
            (Some(_), None, _, _) |
            (None, Some(_), _, _) |
            (_, _, Some(_), None) |
            (_, _, None, Some(_)) => {
                Err(BaconError::SteganographerError(format!("A marker should define both start and end")))
            }
            _ => {
                Ok(MarkdownSteganographer {
                    a_marker,
                    b_marker,
                })
            }
        }
    }

    fn find_first_occurence_of(&self, input_type: ParsedInputType, input: &str) -> Option<usize> {
        match input_type {
            ParsedInputType::A => {
                self.a_marker.start_marker.as_ref()
                    .and_then(|start| input.find(start.as_str()))
            }
            ParsedInputType::B => {
                self.b_marker.start_marker.as_ref()
                    .and_then(|start| input.find(start.as_str()))
            }
            _ => None
        }
    }

    fn parse(&self, input: &str) -> Vec<ParsedInputElement> {
        let mut input = input;
        let mut input_elements: Vec<ParsedInputElement> = Vec::new();

        // Search for either a or b start marker
        loop {
            // Find the first occurrence in the input
            let a_start_index = self.find_first_occurence_of(ParsedInputType::A, input).unwrap_or(input.len());
            let b_start_index = self.find_first_occurence_of(ParsedInputType::B, input).unwrap_or(input.len());

            let (start_index, parsed_input_type) = if a_start_index < b_start_index {
                (a_start_index, ParsedInputType::A)
            } else if b_start_index < a_start_index {
                (b_start_index, ParsedInputType::B)
            } else {
                (input.len(), ParsedInputType::Other)
            };

            let start_size = match parsed_input_type {
                ParsedInputType::A => self.a_marker.start_marker.as_ref().unwrap().len(),
                ParsedInputType::B => self.b_marker.start_marker.as_ref().unwrap().len(),
                _ => 0,
            };
            // Remove the first occurence. From now on, work with tmp
            let tmp: &str = &input[(start_index + start_size)..input.len()];
            let (end_opt, end_size) = match parsed_input_type {
                ParsedInputType::A => (self.a_marker.end_marker.as_ref(), self.a_marker.end_marker_string().len()),
                ParsedInputType::B => (self.b_marker.end_marker.as_ref(), self.b_marker.end_marker_string().len()),
                _ => (None, 0),
            };
            let end_index = (end_opt
                .and_then(|end| tmp.find(end.as_str()))
                // In the case the end marker is not found, return the end of the tmp, minus the end_size
                // (in order not to have out of bounds error since we add the end_size after unwrap_or)
                .unwrap_or(tmp.len() - end_size)) + end_size;
            if end_index > 0 {
                let input_element: &str = &tmp[0..(end_index - end_size)];
                input_elements.push(ParsedInputElement::new(input_element.to_string(), parsed_input_type.clone()));
            } else {
                break;
            }
            if tmp.len() <= end_index {
                input = "";
            } else {
                input = &tmp[end_index..tmp.len()];
            }
        }
        input_elements
    }


    // If b_marker is empty, then all the characters that are not marked with a_marker, should be considered as
    // they are marked with b_marker.
    // Similarly, if a_marker is empty, then all the characters that are not marked with b_marker, should be considered as
    // they are marked with a_marker.
    // This function does exactly this: it takes the parts of `input_string`
    // that have not be characterized as a_marker (if b_marker is None) or b_marker (if a_marker is None)
    // and adds them to the Vec of `ParsedInputElement`s as ParsedInputType::B, or ParsedInputType::B respectively.
    fn replace_unmarked_characters_with(input_string: String, parsed_input_elements: Vec<ParsedInputElement>, start_marker_of_parsed_input_element: &str, end_marker_of_parsed_input_element: &str, parsed_input_type: ParsedInputType) -> Vec<ParsedInputElement> {
        let mut input_string = input_string;
        let mut new_parsed_input_elements: Vec<ParsedInputElement> = Vec::new();
        for pie in parsed_input_elements.into_iter() {
            // This is the string of the ParsedInputElement that is already found
            let parsed_input_element_string = format!("{}{}{}",
                                                      start_marker_of_parsed_input_element,
                                                      pie.string,
                                                      end_marker_of_parsed_input_element);
            // Find this string in the input_string and get its start index
            let index = input_string.find(&parsed_input_element_string).unwrap_or(input_string.len());
            // Get the substring of the input_string until the above index
            let substring: &str = &input_string[0..index];
            // For each character of the substring, create a new ParsedInputElement and push it to the Vec
            for c in substring.chars() {
                new_parsed_input_elements.push(ParsedInputElement::new(c.to_string(), parsed_input_type.clone()));
            }
            // Push the known ParsedInputElement as well to the Vec
            new_parsed_input_elements.push(pie);
            // Change the input string, removing part that was processed in this iteration
            input_string = input_string.replace(&format!("{}{}", substring, parsed_input_element_string), "");
        }
        // Add any remaining ParsedInputElements
        for c in input_string.chars().into_iter() {
            new_parsed_input_elements.push(ParsedInputElement::new(c.to_string(), parsed_input_type.clone()));
        }

        new_parsed_input_elements
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
        let input_string: String = String::from_iter(input.iter());
        let parsed_input_elements = self.parse(&input_string);
        let new_parsed_input_elements: Vec<ParsedInputElement>;
        if self.b_marker.is_empty() {
            new_parsed_input_elements = Self::replace_unmarked_characters_with(input_string, parsed_input_elements, self.a_marker.start_marker.as_ref().unwrap_or(&"".to_string()), self.a_marker.end_marker.as_ref().unwrap_or(&"".to_string()), ParsedInputType::B);
        } else if self.a_marker.is_empty() {
            new_parsed_input_elements = Self::replace_unmarked_characters_with(input_string, parsed_input_elements, self.b_marker.start_marker.as_ref().unwrap_or(&"".to_string()), self.b_marker.end_marker.as_ref().unwrap_or(&"".to_string()), ParsedInputType::A);
        } else {
            new_parsed_input_elements = parsed_input_elements;
        }
        let encoded: Vec<AB> = new_parsed_input_elements.iter()
            .map(|elem| {
                if elem.tp == ParsedInputType::A {
                    let v: Vec<AB> = elem.string.chars()
                        .filter(|sc| sc.is_alphabetic())
                        .map(|_| codec.a())
                        .collect();
                    v
                } else {
                    let v: Vec<AB> = elem.string.chars()
                        .filter(|sc| sc.is_alphabetic())
                        .map(|_| codec.b())
                        .collect();
                    v
                }
            })
            .flat_map(|m| m)
            .collect();
        Ok(codec.decode(&encoded))
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
mod markdown_tests {
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
        let res = MarkdownSteganographer::new(
            Marker::empty(),
            Marker::empty());
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                None),
            Marker::new(
                Some("**"),
                Some("**")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                None,
                Some("**")),
            Marker::new(
                Some("**"),
                Some("**")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::new(
                None,
                Some("**")));
        assert!(res.is_err());
        let res = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::new(
                Some("**"),
                None));
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
    fn disguise_a_secret_to_a_char_array_define_a_marker() {
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
    fn disguise_a_secret_to_a_char_array_define_a_b_markers() {
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
    fn reveal_a_secret_from_a_char_array_define_a_b_markers() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::new(
                Some("*"),
                Some("*")),
            Marker::new(
                Some("!"),
                Some("!"))).unwrap();
        let public = "*T*!h!*i*!s! !is! *a* !pu!*b*!l!*ic* *m*!e!*ss*!a!*ge* *tha*!t! *c*!o!*ntains* !a! *se*!c!*re*!t! *o*ne";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn marker_is_empty() {
        assert!(Marker::empty().is_empty());
        assert!(!Marker::new(Some("*"), Some("*")).is_empty());
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_define_a_marker() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::new(
                Some("**"),
                Some("**")),
            Marker::empty()).unwrap();
        let public = "**T**h**i**s is **a** pu**b**l**ic** **m**e**ss**a**ge** **tha**t **c**o**ntains** a **se**c**re**t **o**ne";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_define_b_marker() {
        let codec = CharCodec::new('a', 'b');
        let s = MarkdownSteganographer::new(
            Marker::empty(),
            Marker::new(
                Some("*"),
                Some("*"))).unwrap();
        let public = "T*h*i*s* *is* a *pu*b*l*ic m*e*ss*a*ge tha*t* c*o*ntains *a* se*c*re*t* one";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }
}