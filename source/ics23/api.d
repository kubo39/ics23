module ics23.api;

import ics23.compress;
import ics23.proofs;
import ics23.verify;

bool verifyMembership(
    CommitmentProof proof,
    ProofSpec spec,
    CommitmentRoot root,
    const(ubyte)[] key,
    const(ubyte)[] value) @trusted
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
    CommitmentRoot root,
    const(ubyte)[] key) @trusted
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
    CommitmentRoot root,
    const(ubyte)[][const(ubyte)[]] items) @trusted
{
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
    CommitmentRoot root,
    const(ubyte)[][] keys) @trusted
{
    auto proof = isCompressed(_proof)
        ? decompress(_proof)
        : _proof;
    foreach (key; keys)
        if (!verifyNonMembership(proof, spec, root, key))
            return false;
    return true;
}

// Fromat of proofs-iavl (immutable-AVL merkle proofs)
ProofSpec iavlSpec() @trusted
{
    auto leaf = new LeafOp;
    leaf.hash = HashOp.SHA256;
    leaf.prehashKey = HashOp.NO_HASH;
    leaf.prehashValue = HashOp.SHA256;
    leaf.length = LengthOp.VAR_PROTO;
    leaf.prefix = [0];

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
ProofSpec tendermintSpec() @trusted
{
    auto leaf = new LeafOp;
    leaf.hash = HashOp.SHA256;
    leaf.prehashKey = HashOp.NO_HASH;
    leaf.prehashValue = HashOp.SHA256;
    leaf.length = LengthOp.VAR_PROTO;
    leaf.prefix = [0];

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

ProofSpec smtSpec() @trusted
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

ExistenceProof getExistProof(CommitmentProof proof, const(ubyte)[] key) @trusted
{
    switch (proof.proofCase)
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
    default:
        assert(false);
    }
}

NonExistenceProof getNonexistProof(CommitmentProof proof, const(ubyte)[] key) @trusted
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
    import std.format : format;
    import std.json;
    import std.meta : AliasSeq;
    import std.typecons;

    auto hexDecode(string hexData)
    {
        ubyte val(char c)
        {
            switch (c)
            {
            case 'A': .. case 'F': return cast(ubyte) (c - 'A' + 10);
            case 'a': .. case 'f': return cast(ubyte) (c - 'a' + 10);
            case '0': .. case '9': return cast(ubyte) (c - '0');
            default: assert(false);
            }
        }

        assert(hexData.length % 2 == 0);
        ubyte[] result;
        size_t cnt = 0;
        auto p = hexData.ptr;
        for (size_t i = 0; i < hexData.length; i += 2)
        {
            result ~= cast(ubyte) (val(p[i]) << 4 | val(p[i + 1]));
        }
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
        import google.protobuf;

        auto contents = readText(filename);
        JSONValue data = parseJSON(contents);
        auto protoBin = hexDecode(data["proof"].str);
        auto commitmentProof = protoBin.fromProtobuf!CommitmentProof;
        RefData refData;
        refData.root = hexDecode(data["root"].str);
        refData.key = hexDecode(data["key"].str);
        if (const(JSONValue)* value = "value" in data)
        {
            refData.value = hexDecode(value.str);
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
            assert(verifyMembership(proof, spec, data.root, data.key, data.value), filename);
        }
        else
        {
            assert(verifyNonMembership(proof, spec, data.root, data.key), filename);
        }
    }

    // iavl spec.
    {
        string[] iavlTestCases = [
            "testdata/iavl/exist_left.json",
            "testdata/iavl/exist_right.json",
            "testdata/iavl/exist_middle.json",
            "testdata/iavl/nonexist_left.json",
            "testdata/iavl/nonexist_right.json",
            "testdata/iavl/nonexist_middle.json"
            ];
        foreach (testCase; iavlTestCases)
        {
            verifyTestData(testCase, iavlSpec());
        }
    }

    // tendermint spec.
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

    // smt spec.
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
