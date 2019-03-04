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
use std::{fmt, result};
use std::error::Error;

pub type Result<T> = result::Result<T, BaconError>;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BaconError {
    GeneralError(String),
    CodecError(String),
    SteganographerError(String),
}

impl fmt::Display for BaconError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &BaconError::GeneralError(ref message) => write!(f, "{}", message),
            &BaconError::CodecError(ref message) => write!(f, "{}", message),
            &BaconError::SteganographerError(ref message) => write!(f, "{}", message),
        }
    }
}

impl Error for BaconError {
    fn description(&self) -> &str {
        match *self {
            BaconError::GeneralError(_) => "A general error occured",
            BaconError::CodecError(_) => "An error coming from a codec occured",
            BaconError::SteganographerError(_) => "An error coming from a steganographer occured",
        }
    }
}
