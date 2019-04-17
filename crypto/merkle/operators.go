package merkle

import (
	"bytes"

	"github.com/tendermint/go-amino"
	"github.com/tendermint/tendermint/crypto/tmhash"
	cmn "github.com/tendermint/tendermint/libs/common"
)

func RunOps(input []byte, opss ...[]ProofOperator) []byte {
	var values [][]byte
	if input != nil {
		values = append(values, input)
	}
	for _, ops := range opss {
		for _, op := range ops {
			var err error
			values, err = op.Run(values)
			if err != nil {
				panic(err)
			}
		}
	}
	return values[0]
}

// Append

type AppendOp struct {
	Prefix []byte `json:"prefix"`
	Suffix []byte `json:"suffix"`
}

var _ ProofOperator = AppendOp{}

const OpTypeAppend = "append"

func (op AppendOp) Argn() int { return 1 }

func (op AppendOp) concat(leaf []byte) []byte {
	buf := new(bytes.Buffer)
	buf.Write(op.Prefix)
	buf.Write(leaf)
	buf.Write(op.Suffix)
	return buf.Bytes()
}

func (op AppendOp) Run(values [][]byte) ([][]byte, error) {
	buf := new(bytes.Buffer)
	buf.Write(values[0])
	res := op.concat(buf.Bytes())
	return [][]byte{res}, nil
}

func (op AppendOp) GetKey() []byte {
	return nil
}

func (op AppendOp) Type() string {
	return OpTypeAppend
}

func (op AppendOp) Encode() []byte {
	buf := new(bytes.Buffer)
	err := amino.EncodeByteSlice(buf, op.Prefix)
	if err == nil {
		amino.EncodeByteSlice(buf, op.Suffix)
	}
	if err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func OpDecoderAppend(op ProofOp) (ProofOperator, error) {
	bz := op.Data

	// TODO: proto? json?

	pref, n, err := amino.DecodeByteSlice(bz)
	if err != nil {
		return nil, err // XXX: cmn.Wrap
	}
	bz = bz[n:]

	suf, n, err := amino.DecodeByteSlice(bz)
	if err != nil {
		return nil, err // XXX: cmn.Wrap
	}
	bz = bz[n:]

	if len(bz) != 0 {
		return nil, cmn.NewError("vvv")
	}

	return AppendOp{
		Prefix: pref,
		Suffix: suf,
	}, nil
}

// SHA256

type SHA256Op struct{}

var _ ProofOperator = SHA256Op{}

const OpTypeSHA256 = "sha256"

func (op SHA256Op) Argn() int { return 1 }

func (op SHA256Op) Run(values [][]byte) ([][]byte, error) {
	hasher := tmhash.New()
	hasher.Write(values[0])
	return [][]byte{hasher.Sum(nil)}, nil
}

func (op SHA256Op) GetKey() []byte {
	return nil
}

func (op SHA256Op) Type() string {
	return OpTypeSHA256
}

func (op SHA256Op) Encode() []byte {
	return nil
}

func OpDecoderSHA256(op ProofOp) (ProofOperator, error) {
	return SHA256Op{}, nil
}

// PrependLength

type PrependLengthOp struct{}

var _ ProofOperator = PrependLengthOp{}

const OpTypePrependLength = "prepend_length"

func (op PrependLengthOp) Argn() int { return 1 }

func (op PrependLengthOp) Run(values [][]byte) ([][]byte, error) {
	buf := new(bytes.Buffer)
	amino.EncodeByteSlice(buf, values[0])
	values[0] = buf.Bytes()
	return values, nil
}

func (op PrependLengthOp) GetKey() []byte {
	return nil
}

func (op PrependLengthOp) Type() string {
	return OpTypePrependLength
}

func (op PrependLengthOp) Encode() []byte {
	return nil
}

func OpDecoderPrependLength(op ProofOp) (ProofOperator, error) {
	return PrependLengthOp{}, nil
}

// Concat

type ConcatOp struct {
	Begin, End int
}

var _ ProofOperator = ConcatOp{}

const OpTypeConcat = "concat"

func (op ConcatOp) Argn() int { return -1 }

func (op ConcatOp) Run(values [][]byte) (res [][]byte, err error) {
	if len(values) < op.End {
		return nil, cmn.NewError("hhh")
	}
	res = append(res, values[:op.Begin]...)
	joined := []byte{}
	for _, v := range values[op.Begin:op.End] {
		joined = append(joined, v...)
	}
	res = append(res, joined)
	res = append(res, values[op.End:]...)
	return
}

func (op ConcatOp) GetKey() []byte {
	return nil
}

func (op ConcatOp) Type() string {
	return OpTypeConcat
}

func (op ConcatOp) Encode() []byte {
	return nil // XXX
}

func OpDecoderConcat(op ProofOp) (ProofOperator, error) {
	return ConcatOp{}, nil // XXX
}

// LiftKeyOp

type LiftKeyOp struct {
	Key []byte
}

var _ ProofOperator = LiftKeyOp{}

var OpTypeLiftKey = "lift_key"

func (op LiftKeyOp) Argn() int { return -1 }

func (op LiftKeyOp) Run(values [][]byte) ([][]byte, error) {
	return append([][]byte{op.Key}, values...), nil
}

func (op LiftKeyOp) GetKey() []byte {
	return op.Key
}

func (op LiftKeyOp) Type() string {
	return OpTypeLiftKey
}

func (op LiftKeyOp) Encode() []byte {
	return nil
}

func OpDecoderLiftKey(op ProofOp) (ProofOperator, error) {
	return LiftKeyOp{
		Key: op.Key,
	}, nil
}

// AssertValuesOp :: n -> n

type AssertValuesOp struct {
	Values [][]byte
}

var _ ProofOperator = AssertValuesOp{}

const OpTypeAssertValues = "assert_values"

func (op AssertValuesOp) Argn() int { return -1 }

func (op AssertValuesOp) Run(values [][]byte) ([][]byte, error) {
	accepted := make(map[string]struct{})
	for _, v := range op.Values {
		accepted[string(v)] = struct{}{}
	}
	for _, v := range values {
		if _, ok := accepted[string(v)]; !ok {
			return nil, cmn.NewError("ttt")
		}
	}
	return values, nil
}

func (op AssertValuesOp) GetKey() []byte {
	return nil
}

func (op AssertValuesOp) Type() string {
	return OpTypeAssertValues
}

func (op AssertValuesOp) Encode() []byte {
	return nil // XXX
}

func OpDecoderAssertValues(op ProofOp) (ProofOperator, error) {
	return AssertValuesOp{}, nil // XXX
}

type ApplyOp struct {
	Ops []ProofOperator
}

var _ ProofOperator = ApplyOp{}

const OpTypeApply = "apply"

func (op ApplyOp) Argn() int { return -1 }

func (op ApplyOp) Run(values [][]byte) (res [][]byte, err error) {
	var ires [][]byte

	for _, iop := range op.Ops {
		argn := iop.Argn()
		if len(values) < argn {
			return nil, cmn.NewError("ddd")
		}
		ires, err = iop.Run(values[:argn])
		if err != nil {
			return
		}
		values = values[argn:]
		res = append(res, ires...)
	}

	return
}

func (op ApplyOp) GetKey() []byte {
	return nil
}

func (op ApplyOp) Type() string {
	return OpTypeApply
}

func (op ApplyOp) Encode() []byte {
	return nil // XXX
}

func OpDecoderApply(op ProofOp) (ProofOperator, error) {
	return ApplyOp{}, nil // XXX
}
