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
    const(ubyte)[] root,
    const(ubyte)[] key,
    const(ubyte)[] value) @trusted
{
    checkExistenceSpec(proof, spec);
    enforce(proof.key == key, "Provided key doesn't match proof");
    enforce(proof.value == value, "Provided value doesn't match proof");

    const calc = calculateExistenceRoot(proof);
    enforce(calc == root, "Root hash dosen't match");
}

void verifyNonExistence(
    NonExistenceProof proof,
    ProofSpec spec,
    const(ubyte)[] root,
    const(ubyte)[] key) @trusted
{
    if (proof.left !is null)
    {
        verifyExistence(proof.left, spec, root, proof.left.key, proof.left.value);
        enforce(key > proof.left.key, "left key isn't before key");
    }
    if (proof.right !is null)
    {
        verifyExistence(proof.right, spec, root, proof.right.key, proof.right.value);
        enforce(key > proof.right.key, "right key isn't after key");
    }
    enforce(spec.innerSpec !is null, "Inner spec missing");

    if (proof.left !is null)
    {
        if (proof.right !is null)
        {
            ensureLeftNeighbor(spec.innerSpec, proof.left.path, proof.right.path);
        }
        else
        {
            ensureRightMost(spec.innerSpec, proof.left.path);
        }
    }
    else
    {
        if (proof.right !is null)
        {
            ensureLeftMost(spec.innerSpec, proof.right.path);
        }
        else
        {
            enforce(false, "neither left nor right proof defined");
        }
    }
}

// Calculate determines the root hash that matches the given proof.
CommitmentRoot calculateExistenceRoot(ExistenceProof proof) @trusted
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

void checkExistenceSpec(ExistenceProof proof, ProofSpec spec) pure @safe
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

unittest
{
    import std.conv : hexString;
    import std.exception : assertNotThrown, assertThrown;
    import ics23.api : iavlSpec;

    struct ExistenceCase
    {
        ExistenceProof proof;
        ProofSpec spec;
        bool valid;
    }

    auto validLeaf = new LeafOp;
    validLeaf.hash = HashOp.SHA256;
    validLeaf.prehashKey = HashOp.NO_HASH;
    validLeaf.prehashValue = HashOp.SHA256;
    validLeaf.length = LengthOp.VAR_PROTO;

    auto invalidLeaf = new LeafOp;
    invalidLeaf.hash = HashOp.SHA512;
    invalidLeaf.prehashKey = HashOp.NO_HASH;
    invalidLeaf.prehashValue = HashOp.NO_HASH;
    invalidLeaf.length = LengthOp.VAR_PROTO;

    auto validInner = new InnerOp;
    validInner.hash = HashOp.SHA256;
    validInner.prefix = cast(ubyte[]) hexString!"deadbeef00cafe00";

    auto invalidInner = new InnerOp;
    invalidInner.hash = HashOp.SHA256;
    invalidInner.prefix = cast(ubyte[]) hexString!"aa";

    auto invalidInnerHash = new InnerOp;
    invalidInnerHash.hash = HashOp.SHA512;
    invalidInnerHash.prefix = cast(ubyte[]) hexString!"deadbeef00cafe00";

    auto depthLimitedSpec = iavlSpec();
    depthLimitedSpec.minDepth = 2;
    depthLimitedSpec.maxDepth = 4;

    ExistenceCase[string] cases;
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        cases["empty proof fails"] = ExistenceCase(proof, iavlSpec(), false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        cases["accept one valid leaf"] = ExistenceCase(proof, iavlSpec(), true);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = invalidLeaf;
        cases["rejects invalid leaf"] = ExistenceCase(proof, iavlSpec(), false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.path = [validInner];
        cases["rejects only inner (no leaf)"] = ExistenceCase(proof, iavlSpec(), false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [validInner];
        cases["accepts leaf and valid inner"] = ExistenceCase(proof, iavlSpec(), true);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [invalidInner];
        cases["rejects invalid inner (prefix)"] = ExistenceCase(proof, iavlSpec(), false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [invalidInnerHash];
        cases["rejects invalid inner (hash)"] = ExistenceCase(proof, iavlSpec(), false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [validInner, validInner, validInner];
        cases["accepts depth limited with proper number of inner nodes"] = ExistenceCase(proof, depthLimitedSpec, true);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [validInner];
        cases["reject depth limited with too few inner nodes"] = ExistenceCase(proof, depthLimitedSpec, false);
    }
    {
        auto proof = new ExistenceProof;
        proof.key = cast(ubyte[]) "foo";
        proof.value = cast(ubyte[]) "bar";
        proof.leaf = validLeaf;
        proof.path = [validInner, validInner, validInner, validInner, validInner];
        cases["reject depth limited with too many inner nodes"] = ExistenceCase(proof, depthLimitedSpec, false);
    }
    foreach (name, tc; cases)
    {
        if (tc.valid)
            assertNotThrown(checkExistenceSpec(tc.proof, tc.spec), name);
        else
            assertThrown(checkExistenceSpec(tc.proof, tc.spec), name);
    }
}

void ensureLeaf(LeafOp leaf, LeafOp leafSpec) pure @safe
{
    enforce(leaf.hash == leafSpec.hash, format!"Unexpected hashOp: %s"(leaf.hash));
    enforce(leaf.prehashKey == leafSpec.prehashKey, format!"Unexpected prehashKey: %s"(leaf.prehashKey));
    enforce(leaf.prehashValue == leafSpec.prehashValue, format!"Unexpected prehashValue: %s"(leaf.prehashValue));
    enforce(leaf.length == leafSpec.length, format!"Unexpected lengthOp: %s"(leaf.length));
    enforce(hasPrefix(leaf.prefix, leafSpec.prefix), format!"Incorrect prefix on leaf: %s"(leaf.prefix));
}

bool hasPrefix(bytes prefix, bytes data) @nogc nothrow pure @safe
{
    if (prefix.length > data.length)
        return false;
    return prefix == data[0 .. prefix.length];
}

void ensureInner(InnerOp inner, ProofSpec spec) pure @safe
{
    enforce(spec.leafSpec !is null, "Spec requires leafSpec");
    enforce(spec.innerSpec !is null, "Spec requires innerSpec");
    enforce(inner.hash == spec.innerSpec.hash, format!"Unexpected hashOp: %s"(inner.hash));
    enforce(!hasPrefix(inner.prefix, spec.leafSpec.prefix), "Inner node with leaf prefix");
    enforce(inner.prefix.length >= spec.innerSpec.minPrefixLength, format!"inner prefix too short: %s"(inner.prefix.length));
    const maxLeftChildBytes = (spec.innerSpec.childOrder.length) - 1 * spec.innerSpec.childSize;
    enforce(inner.prefix.length <= (spec.innerSpec.maxPrefixLength + maxLeftChildBytes), format!"Inner prefix too short: %s"(inner.prefix.length));
}

void ensureLeftMost(InnerSpec spec, InnerOp[] path) pure @trusted
{
    const pad = getPadding(spec, 0);
    foreach (step; path)
    {
        if (!hasPadding(step, pad) && !leftBranchesAreEmpty(spec, step))
            enforce(false, "step not leftmost");
    }
}

void ensureRightMost(InnerSpec spec, InnerOp[] path) pure @trusted
{
    const idx = cast(int) spec.childOrder.length - 1;
    const pad = getPadding(spec, idx);
    foreach (step; path)
    {
        if (!hasPadding(step, pad) && !rightBranchesAreEmpty(spec, step))
            enforce(false, "step not rightmost");
    }
}

void ensureLeftNeighbor(
    InnerSpec spec,
    InnerOp[] left,
    InnerOp[] right) pure @trusted
{
    import std.range;

    auto leftq = left.dup;
    auto rightq = right.dup;

    auto leftqTop = leftq.front;
    leftq.popFront;
    auto rightqTop = rightq.front;
    rightq.popFront;

    while (leftqTop.prefix == rightqTop.prefix && leftqTop.suffix == rightqTop.suffix)
    {
        leftqTop = leftq.front;
        leftq.popFront;
        rightqTop = rightq.front;
        rightq.popFront;
    }

    enforce(isLeftStep(spec, leftqTop, rightqTop), "Not left neighbor at first divergent step");

    ensureRightMost(spec, leftq);
    ensureLeftMost(spec, rightq);
}

bool isLeftStep(
    InnerSpec spec,
    InnerOp left,
    InnerOp right) pure @trusted
{
    const leftIdx = orderFromPadding(spec, left);
    const rightIdx = orderFromPadding(spec, right);
    return leftIdx + 1 == rightIdx;
}

int orderFromPadding(InnerSpec spec, InnerOp op) pure @trusted
{
    const len = cast(int) spec.childOrder.length;
    foreach (branch; 0 .. len)
    {
        const padding = getPadding(spec, branch);
        if (hasPadding(op, padding))
            return branch;
    }
    assert(false, "padding doesn't match any branch");
}

struct Padding
{
    size_t minPrefix;
    size_t maxPrefix;
    size_t suffix;
}

bool hasPadding(InnerOp op, Padding pad) @nogc nothrow pure @safe
{
    return op.prefix.length >= pad.minPrefix
        && op.prefix.length <= pad.maxPrefix
        && op.suffix.length == pad.suffix;
}

Padding getPadding(InnerSpec spec, int branch) pure @trusted
{
    import std.algorithm : countUntil;
    import std.format : format;

    const idx = spec.childOrder.countUntil!(x => x == branch);
    enforce(idx != -1, format!"Branch %d not found"(branch));

    const prefix = idx * spec.childSize;
    const suffix = spec.childSize * (spec.childOrder.length - 1 - idx);
    return Padding(
        prefix + spec.minPrefixLength,
        prefix + spec.maxPrefixLength,
        suffix);
}

// left_branches_are_empty returns true if the padding bytes correspond to all empty children
// on the left side of this branch, ie. it's a valid placeholder on a leftmost path.
bool leftBranchesAreEmpty(InnerSpec spec, InnerOp op) pure @trusted
{
    import std.algorithm : countUntil;
    import std.checkedint : opChecked;

    const leftBranches = cast(size_t) orderFromPadding(spec, op);
    if (leftBranches == 0)
        return false;

    bool overflow;
    const childSize = cast(size_t) spec.childSize;
    const actualPrefix = opChecked!"-"(op.prefix.length, leftBranches * childSize, overflow);
    if (overflow)
        return false;

    foreach (i; 0 .. leftBranches)
    {
        const idx = spec.childOrder.countUntil!(x => x == i);
        const from = actualPrefix + idx * childSize;
        if (spec.emptyChild != op.prefix[from .. from + childSize])
            return false;
    }
    return true;
}

// right_branches_are_empty returns true if the padding bytes correspond to all empty children
// on the right side of this branch, ie. it's a valid placeholder on a rightmost path.
bool rightBranchesAreEmpty(InnerSpec spec, InnerOp op) pure @trusted
{
    import std.algorithm : countUntil;

    const rightBranches = spec.childOrder.length - 1 - orderFromPadding(spec, op);
    if (rightBranches == 0)
        return false;
    if (op.suffix.length != spec.childSize)
        return false;

    foreach (i; 0 .. rightBranches)
    {
        const idx = spec.childOrder.countUntil!(x => x == i);
        const from = idx * spec.childSize;
        if (spec.emptyChild != op.suffix[from .. from + spec.childSize])
            return false;
    }
    return true;
}

unittest
{
    import ics23.api;

    ProofSpec specWithEmptyChild()
    {
        auto leaf = new LeafOp;
        leaf.hash = HashOp.SHA256;
        leaf.prehashKey = HashOp.NO_HASH;
        leaf.prehashValue = HashOp.SHA256;
        leaf.length = LengthOp.NO_PREFIX;
        leaf.prefix = [0];
        auto inner = new InnerSpec;
        inner.childOrder = [0, 1];
        inner.childSize = 32;
        inner.minPrefixLength = 1;
        inner.maxPrefixLength = 1;
        inner.emptyChild = cast(ubyte[]) "32_empty_child_placeholder_bytes";
        inner.hash = HashOp.SHA256;
        auto spec = new ProofSpec;
        spec.leafSpec = leaf;
        spec.innerSpec = inner;
        spec.minDepth = 0;
        spec.maxDepth = 0;
        return spec;
    }

    struct EmptyBranchCase
    {
        InnerOp op;
        ProofSpec spec;
        bool isLeft;
        bool isRight;
    }

    auto spec = specWithEmptyChild();
    auto innerSpec = spec.innerSpec;
    auto emptyChild = innerSpec.emptyChild;

    auto nonEmptySpec = tendermintSpec();
    auto nonEmptyInner = nonEmptySpec.innerSpec;

    EmptyBranchCase[] cases;
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)] ~ emptyChild[];
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, true, false);
    }
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)];
        op.suffix = emptyChild;
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, false, true);
    }

    // non-empty cases
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1),
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0];
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, false, false);
    }
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)];
        op.suffix = [0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0];
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, false, false);
    }
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)] ~ emptyChild[0 .. 28][] ~ cast(ubyte[])"xxxx";
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, false, false);
    }
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)];
        op.suffix = emptyChild[0 .. 28][] ~ cast(ubyte[])"xxxx";
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, spec, false, false);
    }

    // some case using a spec with no empty child.
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1),
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0];
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, nonEmptySpec, false, false);
    }
    {
        auto op = new InnerOp;
        op.prefix = [ubyte(1)];
        op.suffix = [0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0, 0, 0];
        op.hash = innerSpec.hash;
        cases ~= EmptyBranchCase(op, nonEmptySpec, false, false);
    }

    foreach (i, ebc; cases)
    {
        ensureInner(ebc.op, ebc.spec);
        auto inner = ebc.spec.innerSpec;
        assert(ebc.isLeft == leftBranchesAreEmpty(inner, ebc.op));
        assert(ebc.isRight == rightBranchesAreEmpty(inner, ebc.op));
    }
}
