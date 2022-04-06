module ics23.ops;

import std.array : array;
import std.digest.ripemd;
import std.digest.sha;
import std.exception : enforce;

import google.protobuf.common;
import google.protobuf.encoding;

import ics23.helper;
import ics23.proofs;

Hash applyInner(InnerOp inner, const(char)[] child) @trusted
{
    return applyInner(inner, cast(const(ubyte)[]) child);
}

Hash applyInner(InnerOp inner, const(ubyte)[] child) @trusted
{
    enforce(child.length, "Missing child hash");
    auto image = inner.prefix;
    image ~= child;
    image ~= inner.suffix;
    return doHash(inner.hash, image);
}

unittest
{
    import std.conv : hexString;
    {
        auto inner = new InnerOp;
        inner.hash = HashOp.SHA256;
        inner.prefix = cast(bytes) hexString!"0123456789";
        inner.suffix = cast(bytes) hexString!"deadbeef";
        const child = hexString!"00cafe00";
        auto expected = hexString!"0339f76086684506a6d42a60da4b5a719febd4d96d8b8d85ae92849e3a849a5e";
        assert(expected == applyInner(inner, child));
    }
    {
        auto inner = new InnerOp;
        inner.hash = HashOp.SHA256;
        inner.prefix = cast(bytes) hexString!"00204080a0c0e0";
        const child = hexString!"ffccbb997755331100";
        auto expected = hexString!"45bece1678cf2e9f4f2ae033e546fc35a2081b2415edcb13121a0e908dca1927";
        assert(expected == applyInner(inner, child));
    }
}

Hash applyLeaf(LeafOp leaf, const(char)[] key, const(char)[] value) @trusted
{
    return applyLeaf(leaf, cast(const(ubyte)[]) key, cast(const(ubyte)[]) value);
}

Hash applyLeaf(LeafOp leaf, const(ubyte)[] key, const(ubyte)[] value) @trusted
{
    auto hash = leaf.prefix;
    const prekey = prepareLeafData(leaf.prehashKey, leaf.length, key);
    hash ~= prekey;
    const preval = prepareLeafData(leaf.prehashValue, leaf.length, value);
    hash ~= preval;
    return doHash(leaf.hash, hash);
}

unittest
{
    import std.conv : hexString;

    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.NO_HASH;
        leaf.length = LengthOp.NO_PREFIX;
        auto expected = hexString!"c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
        assert(expected == applyLeaf(leaf, "foo", "bar"));
    }
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA512;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.NO_HASH;
        leaf.length = LengthOp.NO_PREFIX;
        auto expected = hexString!"4f79f191298ec7461d60136c60f77c2ae8ddd85dbf6168bb925092d51bfb39b559219b39ae5385ba04946c87f64741385bef90578ea6fe6dac85dbf7ad3f79e1";
        assert(expected == applyLeaf(leaf, "f", "oobaz"));
    }
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.NO_HASH;
        leaf.length = LengthOp.VAR_PROTO;
        auto expected = hexString!"b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265";
        assert(expected == applyLeaf(leaf, "food", "some longer text"));
    }
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.SHA256;
        leaf.length = LengthOp.VAR_PROTO;
        auto expected = hexString!"87e0483e8fb624aef2e2f7b13f4166cda485baa8e39f437c83d74c94bedb148f";
        assert(expected == applyLeaf(leaf, "food", "yet another long string"));
    }
}

private:

Hash prepareLeafData(HashOp prehash, LengthOp length, const(ubyte)[] data) @trusted
{
    enforce(data.length, "Input to prepare data leaf missing");
    auto h = doHash(prehash, data);
    return doLength(length, h);
}

Hash doHash(HashOp hash, const(char)[] data) nothrow pure @trusted
{
    return doHash(hash, cast(const(ubyte)[]) data);
}

Hash doHash(HashOp hash, const(ubyte)[] data) nothrow pure @trusted
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
    import std.conv : hexString;
    {
        auto hash = doHash(HashOp.NO_HASH, "food");
        assert(hash == hexString!"666f6f64");
    }
    {
        auto hash = doHash(HashOp.SHA256, "food");
        assert(hash == hexString!"c1f026582fe6e8cb620d0c85a72fe421ddded756662a8ec00ed4c297ad10676b");
    }
    {
        auto hash = doHash(HashOp.SHA512, "food");
        assert(hash == hexString!"c235548cfe84fc87678ff04c9134e060cdcd7512d09ed726192151a995541ed8db9fda5204e72e7ac268214c322c17787c70530513c59faede52b7dd9ce64331");
    }
    {
        auto hash = doHash(HashOp.RIPEMD160, "food");
        assert(hash == hexString!"b1ab9988c7c7c5ec4b2b291adfeeee10e77cdd46");
    }
    {
        auto hash = doHash(HashOp.BITCOIN, "food");
        assert(hash == hexString!"0bcb587dfb4fc10b36d57f2bba1878f139b75d24");
    }
}

Hash doLength(LengthOp length, const(char)[] data) @trusted
{
    return doLength(length, cast(ubyte[]) data);
}

Hash doLength(LengthOp length, const(ubyte)[] data) @trusted
{
    final switch (length)
    {
    case LengthOp.NO_PREFIX:
        return cast(ubyte[]) data;
    case LengthOp.VAR_PROTO:
        auto len = data.length.toProtobuf.array;
        return len ~ data;
    case LengthOp.REQUIRE_32_BYTES:
        enforce(data.length == 32, "Invalid length");
        return cast(ubyte[]) data;
    case LengthOp.REQUIRE_64_BYTES:
        enforce(data.length == 64, "Invalid length");
        return cast(ubyte[]) data;
    case LengthOp.FIXED32_LITTLE:
        import std.bitmanip;
        auto len = nativeToLittleEndian(cast(uint) data.length);
        return len ~ data;
    case LengthOp.VAR_RLP:
    case LengthOp.FIXED32_BIG:
    case LengthOp.FIXED64_BIG:
    case LengthOp.FIXED64_LITTLE:
        assert(false, "Unsupported length.");
    }
}

unittest
{
    import std.conv : hexString;
    {
        auto prefixed = doLength(LengthOp.NO_PREFIX, "food");
        assert(prefixed == hexString!"666f6f64");
    }
    {
        auto prefixed = doLength(LengthOp.VAR_PROTO, "food");
        assert(prefixed == hexString!"04666f6f64");
    }
    {
        auto prefixed = doLength(LengthOp.FIXED32_LITTLE, "food");
        assert(prefixed == hexString!"04000000666f6f64");
    }
}
