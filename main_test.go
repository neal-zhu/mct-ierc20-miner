package main

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func enc(v interface{}) []byte {
	buf := new(bytes.Buffer)
	rlp.Encode(buf, v)
	return buf.Bytes()
}

func TestT(t *testing.T) {
	txData := "b8dd02f8da015984889dfe048505562bebba8261a894000000000000000000000000000000000000000080b86e646174613a6170706c69636174696f6e2f6a736f6e2c7b2270223a22696572632d706f77222c226f70223a226d696e74222c227469636b223a226574687069222c22626c6f636b223a223138393935323333222c226e6f6e6365223a22313730353131353831333935363930227dc080a01990030c4f00e58e9a1927f1840448e69159f9c20886e8315d572aa78c5d09c5a02a52c90b1b7b155cbcb14b95ba83260c175f10e09c066b04e1851a14ca978416"
	txHash := "0xb4f5e23093bf3d2807b332b7822836b6d9cac3646303bff583ba8e4734b7e8a8"
	var tx types.Transaction
	{
		r := bytes.NewReader(common.Hex2Bytes(txData))
		s := rlp.NewStream(r, 0)
		if err := tx.DecodeRLP(s); err != nil {
			t.Fatal(err)
		}
	}
	v, r, s := tx.RawSignatureValues()

	t.Logf("%x", enc(v))
	t.Logf("%x", enc(r))
	t.Logf("%x", enc(s))
	t.Logf("%x", tx.Data())
	t.Logf("%s", tx.Hash().String())
	t.Logf("%s", txHash)
}
