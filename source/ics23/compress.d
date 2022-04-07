module ics23.compress;

import std.algorithm : map;
import std.array : array;

import ics23.proofs;

bool isCompressed(CommitmentProof proof) @trusted
{
    return proof.proofCase == CommitmentProof.ProofCase.compressed;
}

CommitmentProof compress(CommitmentProof proof)
{
    switch (proof.proofCase)
    {
    case CommitmentProof.ProofCase.batch:
        return compressBatch(proof._batch);
    default:
        return proof;
    }
}

CommitmentProof decompress(CommitmentProof proof)
{
    switch (proof.proofCase)
    {
    case CommitmentProof.ProofCase.compressed:
        return decompressBatch(proof._compressed);
    default:
        return proof;
    }
}

CommitmentProof compressBatch(BatchProof proof)
{
    CompressedBatchEntry[] entries;
    InnerOp[] lookup;
    int[ubyte[]] registry;
    foreach (entry; proof.entries)
    {
        final switch (entry.proofCase)
        {
        case BatchEntry.ProofCase.exist:
            auto exist = compressExist(entry._exist, lookup, registry);
            auto compressed = new CompressedBatchEntry;
            compressed._proofCase = CompressedBatchEntry.ProofCase.exist;
            compressed._exist = exist;
            entries ~= compressed;
            break;
        case BatchEntry.ProofCase.nonexist:
            auto non = entry._nonexist;
            auto left = compressExist(non.left, lookup, registry);
            auto right = compressExist(non.right, lookup, registry);
            auto nonexist = new CompressedNonExistenceProof;
            nonexist.key = non.key;
            nonexist.left = left;
            nonexist.right = right;
            auto compressed = new CompressedBatchEntry;
            compressed._proofCase = CompressedBatchEntry.ProofCase.nonexist;
            compressed._nonexist = nonexist;
            entries ~= compressed;
            break;
        case BatchEntry.ProofCase.proofNotSet:
            entries ~= new CompressedBatchEntry;
            break;
        }
    }
    auto compressedBatchProof = new CompressedBatchProof;
    compressedBatchProof.entries = entries;
    compressedBatchProof.lookupInners = lookup;
    auto commitmentProof = new CommitmentProof;
    commitmentProof._proofCase = CommitmentProof._proofCase.compressed;
    commitmentProof._compressed = compressedBatchProof;
    return commitmentProof;
}

CompressedExistenceProof compressExist(
    ExistenceProof exist,
    InnerOp[] lookup,
    int[ubyte[]] registry)
{
    import google.protobuf.encoding;

    auto path = exist
        .path
        .map!((x) {
            const(ubyte)[] buf = x.toProtobuf.array;
            {
                int* idx = buf in registry;
                if (idx !is null)
                    return *idx;
            }
            const idx = cast(int) lookup.length;
            lookup ~= x;
            registry[buf] = idx;
            return idx;
        })
        .array;

    auto proof = new CompressedExistenceProof;
    proof.key = exist.key;
    proof.value = exist.value;
    proof.leaf = exist.leaf;
    proof.path = path;
    return proof;
}

CommitmentProof decompressBatch(CompressedBatchProof proof)
{
    auto lookup = proof.lookupInners;
    auto entries = proof
        .entries
        .map!((compressedEntry) {
                final switch (compressedEntry.proofCase)
                {
                case CompressedBatchEntry.ProofCase.exist:
                    auto exist = decompressExist(compressedEntry._exist, lookup);
                    auto entry = new BatchEntry;
                    entry._proofCase = BatchEntry.ProofCase.exist;
                    entry._exist = exist;
                    return entry;
                case CompressedBatchEntry.ProofCase.nonexist:
                    auto non = compressedEntry._nonexist;
                    auto left = decompressExist(non.left, lookup);
                    auto right = decompressExist(non.right, lookup);
                    auto nonexist = new NonExistenceProof;
                    nonexist.key = non.key;
                    nonexist.left = left;
                    nonexist.right = right;
                    auto entry = new BatchEntry;
                    entry._proofCase = BatchEntry.ProofCase.nonexist;
                    entry._nonexist = nonexist;
                    return entry;
                case CompressedBatchEntry.ProofCase.proofNotSet:
                    return new BatchEntry;
                }
            })
        .array;

    auto batchProof = new BatchProof;
    batchProof.entries = entries;
    auto commitmentProof = new CommitmentProof;
    commitmentProof._proofCase = CommitmentProof.ProofCase.batch;
    commitmentProof._batch = batchProof;
    return commitmentProof;
}

ExistenceProof decompressExist(CompressedExistenceProof exist, InnerOp[] lookup)
{
    auto path = exist
        .path
        .map!(x => lookup[x])
        .array;
    auto proof = new ExistenceProof;
    proof.key = exist.key;
    proof.value = exist.value;
    proof.leaf = exist.leaf;
    proof.path = path;
    return proof;
}
