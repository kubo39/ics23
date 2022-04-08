# ics23

D client for [ICS23: Vector Commitments].

See also: https://github.com/confio/ics23

## prerequisites

Get protoc-compiler and `protoc-gen-d` from [https://github.com/dcarp/protobuf-d](https://github.com/dcarp/protobuf-d) and run:

```console
protoc --plugin=protoc-gen-d --d_out=./source --proto_path=./ proofs.proto
```

## Test

```console
dub test
```

[ICS23: Vector Commitments]: https://github.com/cosmos/ibc/tree/master/spec/core/ics-023-vector-commitments
