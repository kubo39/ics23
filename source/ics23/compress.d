module ics23.compress;

import ics23.proofs;

bool isCompressed(CommitmentProof proof) @trusted
{
    return proof.proofCase == CommitmentProof.ProofCase.compressed;
}
