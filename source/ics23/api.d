module ics23.api;

import ics23.compress;
import ics23.proofs;
import ics23.verify;

bool verifyMembership(
    CommitmentProof proof,
    ProofSpec spec,
    const(CommitmentRoot) root,
    const(ubyte)[] key,
    const(ubyte)[] value)
{
    auto exist = isCompressed(proof)
        ? getExistProof(decompress(proof), key)
        : getExistProof(proof, key);
    if (exist is null)
        return false;
    verifyExistence(exist, spec, root, key, value);
    return true;
}

bool verifyNonMembership(
    CommitmentProof proof,
    ProofSpec spec,
    const(CommitmentRoot) root,
    const(ubyte)[] key)
{
    auto exist = isCompressed(proof)
        ? getNonexistProof(decompress(proof), key)
        : getNonexistProof(proof, key);
    if (exist is null)
        return false;
    verifyNonExistence(exist, spec, root, key);
    return true;
}

bool verifyBatchMembership(
    CommitmentProof _proof,
    ProofSpec spec,
    const(CommitmentRoot) root,
    const(ubyte)[][const(ubyte)[]] items)
{
    import std.algorithm : all;

    auto proof = isCompressed(_proof)
        ? decompress(_proof)
        : _proof;
    foreach (key, value; items)
        if (!verifyMembership(proof, spec, root, key, value))
            return false;
    return true;
}

bool verifyBatchNonMembership(
    CommitmentProof _proof,
    ProofSpec spec,
    const(CommitmentRoot) root,
    const(ubyte)[][] keys)
{
    import std.algorithm : all;

    auto proof = isCompressed(_proof)
        ? decompress(_proof)
        : _proof;
    foreach (key; keys)
        if (!verifyNonMembership(proof, spec, root, key))
            return false;
    return true;
}

// Fromat of proofs-iavl (immutable-AVL merkle proofs)
ProofSpec iavlSpec()
{
    auto leaf = new LeafOp;
    leaf.hash = HashOp.SHA256;
    leaf.prehashKey = HashOp.NO_HASH;
    leaf.prehashValue = HashOp.SHA256;
    leaf.length = LengthOp.VAR_PROTO;

    auto inner = new InnerSpec;
    inner.childOrder = [0, 1];
    inner.minPrefixLength = 4;
    inner.maxPrefixLength = 12;
    inner.childSize = 33;
    inner.emptyChild = [];
    inner.hash = HashOp.SHA256;

    auto spec = new ProofSpec;
    spec.leafSpec = leaf;
    spec.innerSpec = inner;
    spec.minDepth = 0;
    spec.maxDepth = 0;
    return spec;
}

// Format of proofs-tendermint (crypto/ merkle SimpleProof)
ProofSpec tendermintSpec()
{
    auto leaf = new LeafOp;
    leaf.hash = HashOp.SHA256;
    leaf.prehashKey = HashOp.NO_HASH;
    leaf.prehashValue = HashOp.SHA256;
    leaf.length = LengthOp.VAR_PROTO;

    auto inner = new InnerSpec;
    inner.childOrder = [0, 1];
    inner.minPrefixLength = 1;
    inner.maxPrefixLength = 1;
    inner.childSize = 32;
    inner.emptyChild = [];
    inner.hash = HashOp.SHA256;

    auto spec = new ProofSpec;
    spec.leafSpec = leaf;
    spec.innerSpec = inner;
    spec.minDepth = 0;
    spec.maxDepth = 0;
    return spec;
}

ProofSpec smtSpec()
{
    auto leaf = new LeafOp;
    leaf.hash = HashOp.SHA256;
    leaf.prehashKey = HashOp.NO_HASH;
    leaf.prehashValue = HashOp.SHA256;
    leaf.length = LengthOp.NO_PREFIX;
    leaf.prefix = [0];

    auto inner = new InnerSpec;
    inner.childOrder = [0, 1];
    inner.minPrefixLength = 1;
    inner.maxPrefixLength = 1;
    inner.childSize = 32;
    inner.emptyChild = [0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0];
    inner.hash = HashOp.SHA256;

    auto spec = new ProofSpec;
    spec.leafSpec = leaf;
    spec.innerSpec = inner;
    spec.minDepth = 0;
    spec.maxDepth = 0;
    return spec;
}

private:

ExistenceProof getExistProof(CommitmentProof proof, const(ubyte)[] key)
{
    final switch (proof.proofCase)
    {
    case CommitmentProof.ProofCase.exist:
        return proof._exist;
    case CommitmentProof.ProofCase.batch:
        foreach (entry; proof._batch.entries)
        {
            if (entry.proofCase == BatchEntry.ProofCase.exist &&
                entry._exist.key == key)
            {
                return entry._exist;
            }
        }
        return null;
    case CommitmentProof.ProofCase.proofNotSet:
    case CommitmentProof.ProofCase.nonexist:
    case CommitmentProof.ProofCase.compressed:
        return null;
    }
}

NonExistenceProof getNonexistProof(CommitmentProof proof, const(ubyte)[] key)
{
    final switch (proof.proofCase)
    {
    case CommitmentProof.ProofCase.nonexist:
        return proof._nonexist;
    case CommitmentProof.ProofCase.batch:
        foreach (entry; proof._batch.entries)
        {
            if (entry.proofCase == BatchEntry.ProofCase.nonexist)
            {
                auto non = entry._nonexist;
                if (non.left.key < key && non.right.key > key)
                {
                    return non;
                }
            }
        }
        return null;
    case CommitmentProof.ProofCase.proofNotSet:
    case CommitmentProof.ProofCase.exist:
    case CommitmentProof.ProofCase.compressed:
        return null;
    }
}

unittest
{
    import std.file;
    import std.json;
    import std.meta : AliasSeq;
    import std.typecons;

    // stolen from phobos.
    auto hexStrLiteral(string hexData)
    {
        import std.ascii : isHexDigit;
        char[] result;
        result.length = 1 + hexData.length * 2 + 1;
        auto r = result.ptr;
        r[0] = '"';
        size_t cnt = 0;
        foreach (c; hexData)
        {
            if (c.isHexDigit)
            {
                if ((cnt & 1) == 0)
                {
                    r[1 + cnt]     = '\\';
                    r[1 + cnt + 1] = 'x';
                    cnt += 2;
                }
                r[1 + cnt] = c;
                ++cnt;
            }
        }
        r[1 + cnt] = '"';
        result.length = 1 + cnt + 1;
        return result;
    }

    struct RefData
    {
        const(ubyte)[] root;
        const(ubyte)[] key;
        const(ubyte)[] value;
    }

    auto loadFile(string filename)
    {
        auto contents = readText(filename);
        JSONValue data = parseJSON(contents);
        auto protoBin = hexStrLiteral(data["proof"].str);
        auto commitmentProof = new CommitmentProof;
        RefData refData;
        refData.root = cast(ubyte[]) hexStrLiteral(data["root"].str);
        refData.key = cast(ubyte[]) hexStrLiteral(data["key"].str);
        if (const(JSONValue)* value = "value" in data)
        {
            refData.value = cast(ubyte[]) hexStrLiteral(value.str);
        }
        return tuple(commitmentProof, refData);
    }

    void verifyTestData(string filename, ProofSpec spec)
    {
        CommitmentProof proof;
        RefData data;
        AliasSeq!(proof, data) = loadFile(filename);
        if (data.value !is null)
        {
            verifyMembership(proof, spec, data.root, data.key, data.value);
        }
        else
        {
            verifyNonMembership(proof, spec, data.root, data.key);
        }
    }

    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/exist_left.json", spec);
    }
    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/exist_right.json", spec);
    }
    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/exist_middle.json", spec);
    }
    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/nonexist_left.json", spec);
    }
    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/nonexist_right.json", spec);
    }
    {
        auto spec = iavlSpec();
        verifyTestData("testdata/iavl/nonexist_middle.json", spec);
    }

    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/exist_left.json", spec);
    }
    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/exist_right.json", spec);
    }
    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/exist_middle.json", spec);
    }
    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/nonexist_left.json", spec);
    }
    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/nonexist_right.json", spec);
    }
    {
        auto spec = tendermintSpec();
        verifyTestData("testdata/tendermint/nonexist_middle.json", spec);
    }

    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/exist_left.json", spec);
    }
    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/exist_right.json", spec);
    }
    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/exist_middle.json", spec);
    }
    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/nonexist_left.json", spec);
    }
    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/nonexist_right.json", spec);
    }
    {
        auto spec = smtSpec();
        verifyTestData("testdata/smt/nonexist_middle.json", spec);
    }
}
