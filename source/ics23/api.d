module ics23.api;

import ics23.compress;
import ics23.proofs;
import ics23.verify;

bool verifyMembership(
    CommitmentProof proof,
    ProofSpec spec,
    CommitmentRoot root,
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
    CommitmentRoot root,
    ubyte[] key)
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
