[![Build Status](https://travis-ci.org/astonbitecode/bacon-cipher.svg?branch=master)](https://travis-ci.org/astonbitecode/bacon-cipher)
[![codecov](https://codecov.io/gh/astonbitecode/bacon-cipher/branch/master/graph/badge.svg)](https://codecov.io/gh/astonbitecode/bacon-cipher)

# bacon-cipher

An implementation of the [Bacon's cipher](https://en.wikipedia.org/wiki/Bacon%27s_cipher).

## Quick example

```rust
use bacon_cipher::codecs::char_codec::CharCodec;
use bacon_cipher::BaconCodec;
use std::iter::FromIterator;

let codec = CharCodec::default();
let encoded = codec.encode(&['M', 'y', ' ', 's', 'e', 'c', 'r', 'e', 't']);
let string = String::from_iter(encoded.iter());

assert_eq!("ABABBBABBABAAABAABAAAAABABAAAAAABAABAABA", string);
```

## Licence

Apache License, Version 2.0, (http://www.apache.org/licenses/LICENSE-2.0)