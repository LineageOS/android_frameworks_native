# libbufferstreams: Reactive Streams for Graphics Buffers

This library is currently **experimental** and **under active development**.
It is not production ready yet.

For more information on reactive streams, please see <https://www.reactive-streams.org/>

## Contributing

This library is natively written in Rust and exposes a C API. If you make changes to the Rust API,
you **must** update the C API in turn. To do so, with cbindgen installed, run:

```$ ./update_include.sh```
