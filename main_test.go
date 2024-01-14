package main

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
)

func enc(v interface{}) []byte {
	buf := new(bytes.Buffer)
	rlp.Encode(buf, v)
	return buf.Bytes()
}

func BenchmarkCPU(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CPUKeccakHash([]byte("hello"))
	}
}

func BenchmarkGPU(b *testing.B) {
	for i := 0; i < b.N; i++ {
		KeccakHash([]byte("hello"))
	}
}
