module ics23.ops;

import std.array : array;
import std.digest.ripemd;
import std.digest.sha;

import google.protobuf.encoding;

import ics23.helper;
import ics23.proofs;

Hash applyInner(InnerOp inner, const(ubyte)[] child)
{
    assert(child.length);
    auto image = inner.prefix;
    image ~= child;
    image ~= inner.suffix;
    return doHash(inner.hash, image);
}

Hash applyLeaf(LeafOp leaf, const(ubyte)[] key, const(ubyte)[] value)
{
    auto hash = leaf.prefix;
    const prekey = prepareLeafData(leaf.prehashKey, leaf.length, key);
    hash ~= prekey;
    const preval = prepareLeafData(leaf.prehashValue, leaf.length, value);
    hash ~= preval;
    return doHash(leaf.hash, hash);
}

private:

Hash prepareLeafData(HashOp prehash, LengthOp length, const(ubyte)[] data)
{
    assert(data.length);
    auto h = doHash(prehash, data);
    return doLength(length, h);
}

Hash doHash(HashOp hash, const(char)[] data)
{
    return doHash(hash, cast(const(ubyte)[]) data);
}

Hash doHash(HashOp hash, const(ubyte)[] data)
{
    final switch (hash)
    {
    case HashOp.NO_HASH:
        return cast(ubyte[]) data;
    case HashOp.SHA256:
        return sha256Of(data).dup;
    case HashOp.SHA512:
        return sha512Of(data).dup;
    case HashOp.RIPEMD160:
        return ripemd160Of(data).dup;
    case HashOp.BITCOIN:
        return ripemd160Of(sha256Of(data)[]).dup;
    case HashOp.KECCAK:
    case HashOp.SHA512_256:
        assert(false, "Unsupported hash.");
    }
}

unittest
{
    import std.digest;
    {
        auto hash = doHash(HashOp.NO_HASH, "food");
        assert(hash.toHexString!(LetterCase.lower) == "666f6f64");
    }
    {
        auto hash = doHash(HashOp.SHA256, "food");
        assert(hash.toHexString!(LetterCase.lower) == "c1f026582fe6e8cb620d0c85a72fe421ddded756662a8ec00ed4c297ad10676b");
    }
    {
        auto hash = doHash(HashOp.SHA512, "food");
        assert(hash.toHexString!(LetterCase.lower) == "c235548cfe84fc87678ff04c9134e060cdcd7512d09ed726192151a995541ed8db9fda5204e72e7ac268214c322c17787c70530513c59faede52b7dd9ce64331");
    }
    {
        auto hash = doHash(HashOp.RIPEMD160, "food");
        assert(hash.toHexString!(LetterCase.lower) == "b1ab9988c7c7c5ec4b2b291adfeeee10e77cdd46");
    }
    {
        auto hash = doHash(HashOp.BITCOIN, "food");
        assert(hash.toHexString!(LetterCase.lower) == "0bcb587dfb4fc10b36d57f2bba1878f139b75d24");
    }
}

Hash doLength(LengthOp length, const(char)[] data)
{
    return doLength(length, cast(ubyte[]) data);
}

Hash doLength(LengthOp length, const(ubyte)[] data)
{
    final switch (length)
    {
    case LengthOp.NO_PREFIX:
        return cast(ubyte[]) data;
    case LengthOp.VAR_PROTO:
        auto len = data.length.toProtobuf.array;
        return len ~ data;
    case LengthOp.REQUIRE_32_BYTES:
        assert(data.length == 32);
        return cast(ubyte[]) data;
    case LengthOp.REQUIRE_64_BYTES:
        assert(data.length == 64);
        return cast(ubyte[]) data;
    case LengthOp.VAR_RLP:
    case LengthOp.FIXED32_BIG:
    case LengthOp.FIXED32_LITTLE:
    case LengthOp.FIXED64_BIG:
    case LengthOp.FIXED64_LITTLE:
        assert(false, "Unsupported length.");
    }
}

unittest
{
    import std.digest;
    {
        auto prefixed = doLength(LengthOp.NO_PREFIX, "food");
        assert(prefixed.toHexString!(LetterCase.lower) == "666f6f64");
    }
    {
        auto prefixed = doLength(LengthOp.VAR_PROTO, "food");
        assert(prefixed.toHexString!(LetterCase.lower) == "04666f6f64");
    }
}
