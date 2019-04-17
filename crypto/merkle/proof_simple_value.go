package merkle

import ()

// SimpleKVLeafOp is the proof for the leafs generated from
// SimpleProofsFromMap(). It checks key and automatically appends it to the
// provided values.
//
// SimpleKVLeafOp =
// SHA256Op
// PrependLengthOp
// LiftKeyOp
// PrependLengthOp
// ConcatOp
var opValidatorSimpleKVLeaf = Sequence(
	OpType(OpTypeSHA256),
	OpType(OpTypePrependLength),
	OpType(OpTypeLiftKey),
	OpType(OpTypePrependLength),
	OpType(OpTypeConcat),
)

func OpValidatorSimpleKVLeaf(ops []ProofOperator) ([]ProofOperator, error) {
	return opValidatorSimpleKVLeaf(ops)
}

// SimpleValueOp takes a key and a single value as argument and
// produces the root hash.  The corresponding tree structure is
// the SimpleMap tree.  SimpleMap takes a Hasher, and currently
// Tendermint uses aminoHasher.  SimpleValueOp should support
// the hash function as used in aminoHasher.  TODO support
// additional hash functions here as options/args to this
// operator.
//
// SimpleValueOp =
// optional SimpleKVLeafOp
// AppendOp
// SHA256Op
// AssertValuesOp
// repeated {
//   AppendOp
//   SHA256Op
// }
var opValidatorSimpleValue = Sequence(
	Option(OpValidatorSimpleKVLeaf),
	OpType(OpTypeAppend),
	OpType(OpTypeSHA256),
	OpType(OpTypeAssertValues),
	Repeat(Sequence(
		OpType(OpTypeAppend),
		OpType(OpTypeSHA256),
	)),
)

func OpValidatorSimpleValue(ops []ProofOperator) ([]ProofOperator, error) {
	return opValidatorSimpleValue(ops)
}
