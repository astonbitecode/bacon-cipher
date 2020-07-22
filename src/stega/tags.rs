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
use html5ever::parse_document;
use html5ever::rcdom::{Handle, NodeData, RcDom};
use html5ever::tendril::TendrilSink;

use crate::{BaconCodec, errors, Steganographer};

#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    start_node: Option<String>,
    end_node: Option<String>,
}

impl Tag {
    pub fn new(start_node: Option<&str>, end_node: Option<&str>) -> Tag {
        Tag {
            start_node: start_node.map(|node| node.to_string()),
            end_node: end_node.map(|node| node.to_string()),
        }
    }

    pub fn empty() -> Tag {
        Tag {
            start_node: None,
            end_node: None,
        }
    }

    pub fn start_node(&self) -> &Option<String> {
        &self.start_node
    }

    pub fn end_node(&self) -> &Option<String> {
        &self.end_node
    }

    pub fn start_node_string(&self) -> String {
        self.start_node().clone().unwrap_or("".to_string())
    }

    pub fn end_node_string(&self) -> String {
        self.end_node().clone().unwrap_or("".to_string())
    }
}

pub struct SimpleTagSteganographer {
    a_tag: Tag,
    b_tag: Tag,
    optimize_disguise: bool,
}

impl SimpleTagSteganographer {
    pub fn new(a_tag: Tag, b_tag: Tag) -> SimpleTagSteganographer {
        SimpleTagSteganographer {
            a_tag,
            b_tag,
            optimize_disguise: true,
        }
    }

    pub fn no_optimize_disguise_output(mut self) -> Self {
        self.set_optimize_disguise(false);
        self
    }

    pub fn set_optimize_disguise(&mut self, b: bool) {
        self.optimize_disguise = b;
    }

    fn parse(&self, handle: &Handle) -> Vec<ParsedInputElement> {
        let mut acc = Vec::new();
        self.do_parse(handle, &mut acc, None);
        acc
    }

    fn do_parse(&self, handle: &Handle, acc: &mut Vec<ParsedInputElement>, parent_element_type: Option<ParsedInputType>) {
        let mut current_element_type = None;

        match handle.data {
            NodeData::Text { ref contents } => {
                match parent_element_type {
                    Some(ParsedInputType::A) => acc.push(ParsedInputElement::new(contents.borrow().to_string(), ParsedInputType::A)),
                    Some(ParsedInputType::B) => acc.push(ParsedInputElement::new(contents.borrow().to_string(), ParsedInputType::B)),
                    Some(ParsedInputType::Other) => {
                        if self.a_tag.start_node.is_none() {
                            acc.push(ParsedInputElement::new(contents.borrow().to_string(), ParsedInputType::A))
                        } else if self.b_tag.start_node.is_none() {
                            acc.push(ParsedInputElement::new(contents.borrow().to_string(), ParsedInputType::B))
                        }
                    }
                    None => { /* ignore */ }
                }
            }
            NodeData::Element {
                ref name,
                ..
            } => {
                let name = format!("<{}>", name.local);
                if name == self.a_tag.start_node_string() {
                    current_element_type = Some(ParsedInputType::A);
                } else if name == self.b_tag.start_node_string() {
                    current_element_type = Some(ParsedInputType::B);
                } else {
                    current_element_type = Some(ParsedInputType::Other);
                }
            }
            _ => { /* ignore */ }
        }

        for child in handle.children.borrow().iter() {
            self.do_parse(&child, acc, current_element_type.clone());
        }
    }
}

impl Steganographer for SimpleTagSteganographer {
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
                                                self.a_tag.start_node_string(),
                                                pc.clone(),
                                                self.a_tag.end_node_string()));
                    i = i + 1;
                } else if opt.is_some() && codec.is_b(opt.unwrap()) {
                    disguised.push_str(&format!("{}{}{}",
                                                self.b_tag.start_node_string(),
                                                pc.clone(),
                                                self.b_tag.end_node_string()));
                    i = i + 1;
                } else {
                    disguised.push(pc.clone())
                }
            } else {
                disguised.push(pc.clone())
            }
        }

        if self.optimize_disguise {
            Ok(disguised
                .replace(&format!("{}{}", self.a_tag.end_node_string(), self.a_tag.start_node_string()), "")
                .replace(&format!("{}{}", self.b_tag.end_node_string(), self.b_tag.start_node_string()), "")
                .chars().collect())
        } else {
            Ok(disguised.chars().collect())
        }
    }

    fn reveal<AB>(&self, input: &[char], codec: &dyn BaconCodec<ABTYPE=AB, CONTENT=Self::T>) -> errors::Result<Vec<char>> {
        let input_iter: Vec<String> = input.iter().map(|ch| ch.to_string()).collect();
        let dom = parse_document(RcDom::default(), Default::default()).from_iter(input_iter);

        let encoded: Vec<AB> = self.parse(&dom.document).iter()
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
mod tag_tests {
    use std::iter::FromIterator;

    use html5ever::parse_document;
    use html5ever::rcdom::RcDom;
    use html5ever::tendril::TendrilSink;

    use crate::codecs::char_codec::CharCodec;

    use super::*;

    #[test]
    fn tags_creation() {
        let tag1 = Tag::new(None, None);
        assert!(tag1.start_node() == &None);
        assert!(tag1.end_node() == &None);

        let tag2 = Tag::new(Some("<tag>"), Some("</tag>"));
        assert!(tag2.start_node() == &Some("<tag>".to_string()));
        assert!(tag2.end_node() == &Some("</tag>".to_string()));

        let tag3 = Tag::empty();
        assert!(tag3.start_node() == &None);
        assert!(tag3.end_node() == &None);
    }

    #[test]
    fn tag_nodes_to_string() {
        let tag = Tag::new(Some("<tag>"), Some("</tag>"));
        assert!(tag.start_node_string() == ("<tag>"));
        assert!(tag.end_node_string() == ("</tag>"));
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_b_tag() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<b>"),
                Some("</b>")));

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "T<b>h</b>i<b>s</b> <b>is</b> a <b>pu</b>b<b>l</b>ic m<b>e</b>ss<b>a</b>ge tha<b>t</b> c<b>o</b>ntains <b>a</b> se<b>c</b>re<b>t</b> one");
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_a_tag() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::new(
                Some("<b>"),
                Some("</b>")),
            Tag::empty());

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "<b>T</b>h<b>i</b>s is <b>a</b> pu<b>b</b>l<b>ic</b> <b>m</b>e<b>ss</b>a<b>ge</b> <b>tha</b>t <b>c</b>o<b>ntains</b> a <b>se</b>c<b>re</b>t <b>o</b>ne");
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_define_a_b_tags() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::new(
                Some("<i>"),
                Some("</i>")),
            Tag::new(
                Some("<b>"),
                Some("</b>")));

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "<i>T</i><b>h</b><i>i</i><b>s</b> <b>is</b> <i>a</i> <b>pu</b><i>b</i><b>l</b><i>ic</i> <i>m</i><b>e</b><i>ss</i><b>a</b><i>ge</i> <i>tha</i><b>t</b> <i>c</i><b>o</b><i>ntains</i> <b>a</b> <i>se</i><b>c</b><i>re</i><b>t</b> <i>o</i>ne");
    }

    #[test]
    fn disguise_a_secret_to_a_char_array_no_output_optimization() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<b>"),
                Some("</b>")))
            .no_optimize_disguise_output();

        let public = "This is a public message that contains a secret one";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "T<b>h</b>i<b>s</b> <b>i</b><b>s</b> a <b>p</b><b>u</b>b<b>l</b>ic m<b>e</b>ss<b>a</b>ge tha<b>t</b> c<b>o</b>ntains <b>a</b> se<b>c</b>re<b>t</b> one");
    }

    #[test]
    fn disguise_a_secret_to_a_short_char_array() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<b>"),
                Some("</b>")));

        let public = "Short public";
        let output = s.disguise(
            &['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't'],
            &Vec::from_iter(public.chars()),
            &codec);
        let string = String::from_iter(output.unwrap().iter());
        assert!(string == "S<b>h</b>o<b>rt</b> <b>p</b>u<b>bl</b>i<b>c</b>");
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_define_b_tag() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<b>"),
                Some("</b>")));
        let public = "T<b>h</b>i<b>s</b> <b>i</b><b>s</b> a <b>p</b><b>u</b>b<b>l</b>ic m<b>e</b>ss<b>a</b>ge tha<b>t</b> c<b>o</b>ntains <b>a</b> se<b>c</b>re<b>t</b> one";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_define_a_tag() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::new(
                Some("<b>"),
                Some("</b>")),
            Tag::empty());
        let public = "<b>T</b>h<b>i</b>s is <b>a</b> pu<b>b</b>l<b>ic</b> <b>m</b>e<b>ss</b>a<b>ge</b> <b>tha</b>t <b>c</b>o<b>ntains</b> a <b>se</b>c<b>re</b>t <b>o</b>ne";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_define_a_b_tags() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::new(
                Some("<i>"),
                Some("</i>")),
            Tag::new(
                Some("<b>"),
                Some("</b>")));
        let public = "<i>T</i><b>h</b><i>i</i><b>s</b> <b>is</b> <i>a</i> <b>pu</b><i>b</i><b>l</b><i>ic</i> <i>m</i><b>e</b><i>ss</i><b>a</b><i>ge</i> <i>tha</i><b>t</b> <i>c</i><b>o</b><i>ntains</i> <b>a</b> <i>se</i><b>c</b><i>re</i><b>t</b> <i>o</i>ne";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn reveal_a_secret_from_a_char_array_elements_contain_non_alphabetic_characters_too() {
        let codec = CharCodec::new('a', 'b');
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<b>"),
                Some("</b>")));
        // The public string contains <b>p111u</b>. The 111 should be ignored
        let public = "T<b>h</b>i<b>s</b> <b>is</b> a <b>p111u</b>b<b>l</b>ic m<b>e</b>ss<b>a</b>ge tha<b>t</b> c<b>o</b>ntains <b>a</b> se<b>c</b>re<b>t</b> one";
        let output = s.reveal(
            &Vec::from_iter(public.chars()),
            &codec);
        assert!(output.is_ok());
        let string = String::from_iter(output.unwrap().iter());
        assert!(string.starts_with("MYSECRET"));
    }

    #[test]
    fn parse_a_document_to_tags() {
        let document = "<grandparent><parent>childB1</parent>childA<parent>childB2</parent></grandparent>";
        let input_iter: Vec<String> = document.chars().map(|ch| ch.to_string()).collect();
        let dom = parse_document(RcDom::default(), Default::default()).from_iter(input_iter);
        let s = SimpleTagSteganographer::new(
            Tag::empty(),
            Tag::new(
                Some("<parent>"),
                Some("</parent>")));
        let parse_result = s.parse(&dom.document);
        assert_eq!(parse_result.len(), 3);
        assert!(parse_result.contains(&ParsedInputElement::new("childB1".to_string(), ParsedInputType::B)));
        assert!(parse_result.contains(&ParsedInputElement::new("childB2".to_string(), ParsedInputType::B)));
        assert!(parse_result.contains(&ParsedInputElement::new("childA".to_string(), ParsedInputType::A)));
    }
}