# BitVM Toy Implementation

A work-in-progress toy-implementation of BitVM. This is still extremely experimental code which's purpose is mostly for us to figure out how to build BitVM. This project is only meant to be a draft or blueprint for a proper implementation in Rust.

That's why it is totally messy and not documented. We will clean this up asap.



## Development 

Serve the root directory with a local web server. For example, Python3 `python3 -m http.server 7777` or Python2: `python -m SimpleHTTPServer 7777`. Then open http://localhost:7777/run

## Bitcoin Script Interpreter

Our Bitcoin Script [interpreter](https://bitvm.github.io/BitVM/run/interpreter.html) is a tool to develop complex Bitcoin Scripts.