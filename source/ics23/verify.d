module ics23.verify;

import std.exception : enforce;
import std.format : format;

import google.protobuf.common;

import ics23.ops;
import ics23.proofs;

alias CommitmentRoot = ubyte[];

void verifyExistence(
    ExistenceProof proof,
    ProofSpec spec,
    ubyte[] root,
    ubyte[] key,
    ubyte[] value)
{
    checkExistenceSpec(proof, spec);
    enforce(proof.key == key, "Provided key doesn't match proof");
    enforce(proof.value == value, "Provided value doesn't match proof");

    const calc = calculateExistenceRoot(proof);
    enforce(calc == root, "Root hash dosen't match");
}

// Calculate determines the root hash that matches the given proof.
CommitmentRoot calculateExistenceRoot(ExistenceProof proof)
{
    enforce(proof.key.length, "Existence proof must have key set");
    enforce(proof.value.length, "Existence proof must have value set");
    auto hash = applyLeaf(proof.leaf, proof.key, proof.value);
    foreach (step; proof.path)
        hash = applyInner(step, hash);
    return hash;
}

unittest
{
    import std.conv : hexString;
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.NO_HASH;
        leaf.length = LengthOp.VAR_PROTO;
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "food";
        proof.value = cast(ubyte[]) "some longer text";
        proof.leaf = leaf;

        auto expected = hexString!"b68f5d298e915ae1753dd333da1f9cf605411a5f2e12516be6758f365e6db265";
        assert(expected == calculateExistenceRoot(proof));
    }
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.NO_HASH;
        leaf.length = LengthOp.VAR_PROTO;

        auto inner = new InnerOp;
        inner.hash = HashOp.SHA256;
        inner.prefix = cast(bytes) hexString!"deadbeef00cafe00";

        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "food";
        proof.value = cast(ubyte[]) "some longer text";
        proof.leaf = leaf;
        proof.path = [inner];

        auto expected = hexString!"836ea236a6902a665c2a004c920364f24cad52ded20b1e4f22c3179bfe25b2a9";
        assert(expected == calculateExistenceRoot(proof));
    }
}

private:

void checkExistenceSpec(ExistenceProof proof, ProofSpec spec)
{
    enforce(proof.leaf !is null, "Leaf must be set");
    enforce(spec.leafSpec !is null, "LeafSpec must be set");
    ensureLeaf(proof.leaf, spec.leafSpec);
    if (spec.minDepth != 0)
    {
        enforce(proof.path.length >= spec.minDepth, format!"Too few InnerOps: %s"(proof.path.length));
        enforce(proof.path.length <= spec.maxDepth, format!"Too many InnerOps: %s"(proof.path.length));
    }
    foreach (step; proof.path)
    {
        ensureInner(step, spec);
    }
}

void ensureLeaf(LeafOp leaf, LeafOp leafSpec)
{
    enforce(leaf.hash == leafSpec.hash, format!"Unexpected hashOp: %s"(leaf.hash));
    enforce(leaf.prehashKey == leafSpec.prehashKey, format!"Unexpected prehashKey: %s"(leaf.prehashKey));
    enforce(leaf.prehashValue == leafSpec.prehashValue, format!"Unexpected prehashValue: %s"(leaf.prehashValue));
    enforce(leaf.length == leafSpec.length, format!"Unexpected lengthOp: %s"(leaf.length));
    enforce(hasPrefix(leaf.prefix, leafSpec.prefix), format!"Incorrect prefix on leaf: %s"(leaf.prefix));
}

bool hasPrefix(bytes prefix, bytes data)
{
    if (prefix.length > data.length)
        return false;
    return prefix == data[0 .. prefix.length];
}

void ensureInner(InnerOp inner, ProofSpec spec)
{
    enforce(spec.leafSpec !is null, "Spec requires leafSpec");
    enforce(spec.innerSpec !is null, "Spec requires innerSpec");
    enforce(inner.hash == spec.innerSpec.hash, format!"Unexpected hashOp: %s"(inner.hash));
    enforce(!hasPrefix(inner.prefix, spec.leafSpec.prefix), "Inner node with leaf prefix");
    enforce(inner.prefix.length >= spec.innerSpec.minPrefixLength, format!"inner prefix too short: %s"(inner.prefix.length));
    const maxLeftChildBytes = (spec.innerSpec.childOrder.length) - 1 * spec.innerSpec.childSize;
    enforce(inner.prefix.length <= (spec.innerSpec.maxPrefixLength + maxLeftChildBytes), format!"Inner prefix too short: %s"(inner.prefix.length));
}
