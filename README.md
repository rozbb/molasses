Molasses
========

[![Build Status](https://travis-ci.org/trailofbits/molasses.svg?branch=master)](https://travis-ci.org/trailofbits/molasses)
[![Coverage](https://codecov.io/gh/trailofbits/molasses/branch/master/graph/badge.svg)](https://codecov.io/gh/trailofbits/molasses)

An extremely early implementation of the [Message Layer Security](https://mlswg.github.io/) group
messaging protocol. This repo is based on
[draft 4](https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/04/) of the MLS protocol
specification. To build internal docs, do

```
cargo doc --document-private-items
```

Example Usage
-------------
See [examples/sample_interaction.rs](examples/sample_interaction.rs) for an example of how to use
this crate. To run the example, do

```
cargo run --example sample_interaction
```

Warning
-------

This software should *not* be used in any security-sensitive contexts. Use at your own risk.

License
-------

Licensed under Apache License, Version 2.0, ([LICENSE](LICENSE))
