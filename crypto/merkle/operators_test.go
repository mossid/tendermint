package merkle

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func randomGenerateProofOperator() ProofOperator {
	switch rand.Intn(5) {
	case 0:
		res := AppendOp{
			Prefix: make([]byte, 32),
			Suffix: make([]byte, 32),
		}
		rand.Read(res.Prefix)
		rand.Read(res.Suffix)
		return res
	case 1:
		return SHA256Op{}
	case 2:
		return PrependLengthOp{}
	case 3:
		/*
			return ConcatOp{
				Begin: rand.Int(),
				End:   rand.Int(),
			}
		*/
		return ConcatOp{}
	case 4:
		res := LiftKeyOp{
			Key: make([]byte, 32),
		}
		rand.Read(res.Key)
		return res
		/*
			case 5:
				res := AssertValuesOp{
					Values: make([][]byte, 8),
				}
				for i := range res.Values {
					rand.Read(res.Values[i])
				}
				return res
			case 6:
				res := ApplyOp{
					Ops: make([]ProofOperator, 4),
				}
				for i := range res.Ops {
					res.Ops[i] = randomGenerateProofOperator()
				}
				return res
		*/
	default:
		panic("should not reach here")
	}
}

func TestOperatorsEncodeDecode(t *testing.T) {
	prt := DefaultProofRuntime()
	for i := 0; i < 1000; i++ {
		op := randomGenerateProofOperator()
		pop, err := prt.DecodeProof(&Proof{Ops: []ProofOp{ToProofOp(op)}})
		require.NoError(t, err)
		require.Equal(t, op, pop[0])
	}
}
