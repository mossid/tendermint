package merkle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMapSimpleValueOp(t *testing.T) {
	tcs := []map[string][]byte{
		map[string][]byte{
			"key1": []byte("elem1"),
			"key2": []byte("elem2"),
			"key3": []byte("elem3"),
		},
	}

	for _, tc := range tcs {
		root, proofs, _ := SimpleProofsFromMap(tc)
		for k, proof := range proofs {
			// Verify we can generate merkle operators from the SimpleProof
			// and it can be validated by the validator
			ops := proof.MakeProofOps([]byte(k))
			require.NotNil(t, ops)
			require.NoError(t, ValidateProofOperators(OpValidatorSimpleValue, ops))
			// Run the operators and check if the result is equal with the root
			args := [][]byte{tc[k]}
			var err error
			for _, op := range ops {
				args, err = op.Run(args)
				require.NoError(t, err)
			}
			require.Equal(t, root, args[0])
		}
	}
}

func TestByteSliceSimpleValueOp(t *testing.T) {
	tcs := [][][]byte{
		[][]byte{[]byte("elem1"), []byte("elem2"), []byte("elem3")},
	}

	for _, tc := range tcs {
		root, proofs := SimpleProofsFromByteSlices(tc)
		for i, proof := range proofs {
			ops := proof.MakeProofOps(nil)
			require.NotNil(t, ops)
			require.NoError(t, ValidateProofOperators(OpValidatorSimpleValue, ops))
			args := [][]byte{tc[i]}
			var err error
			for _, op := range ops {
				args, err = op.Run(args)
				require.NoError(t, err)
			}
			require.Equal(t, root, args[0])
		}
	}
}
