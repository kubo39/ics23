module ics23.api;

import ics23.proofs;
import ics23.verify;

bool verifyMembership(
    CommitmentProof proof,
    ProofSpec spec,
    CommitmentRoot root,
    ubyte[] key,
    ubyte[] value)
{
    auto exist = getExistProof(proof, key);
    if (exist is null)
        return false;
    verifyExistence(exist, spec, root, key, value);
    return true;
}

private:

ExistenceProof getExistProof(CommitmentProof proof, ubyte[] key)
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
        assert(false);
    }
}
