package poolscript

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

const (
	numOperations = 1000
)

func TestSignature(t *testing.T) {
	opHash, err := chainhash.NewHashFromStr("17ce8d7556f0b9fece822647c2470b3e542db3edd6d931954a09fb54024f868d")
	require.NoError(t, err)

	witness := wire.TxWitness{{
		0x30, 0x44, 0x02, 0x20, 0x1c, 0x19, 0xcd, 0xc7, 0x52, 0x72, 0xd0, 0xeb, 0xb2, 0xb1, 0xd4, 0x19,
		0x29, 0x74, 0x65, 0x64, 0x1a, 0xd2, 0x84, 0x0d, 0xa7, 0xa1, 0x25, 0x99, 0x99, 0x9c, 0x85, 0xc2,
		0x74, 0xfa, 0x4c, 0x52, 0x02, 0x20, 0x1e, 0xe2, 0x38, 0x35, 0x6e, 0x37, 0xb4, 0xac, 0xf3, 0x78,
		0xab, 0x6e, 0xb2, 0x2c, 0xaf, 0x93, 0xa8, 0x2b, 0x3b, 0x87, 0xbe, 0xca, 0x24, 0x52, 0x99, 0xdd,
		0x8b, 0x06, 0x72, 0xcb, 0x89, 0xf0, 0x01,
	}, {
		//0x30, 0x45, 0x02, 0x21, 0x00, 0xae, 0x93, 0x41, 0x66, 0x68, 0xbe, 0x02, 0xfe, 0xe4, 0xfd, 0x7c,
		//0xe6, 0x5a, 0x41, 0x0b, 0xf8, 0xbd, 0x6f, 0x48, 0x61, 0x89, 0x1c, 0x18, 0x29, 0x9c, 0x4a, 0x6e,
		//0x36, 0x3a, 0xe9, 0x4f, 0x6b, 0x02, 0x20, 0x74, 0x35, 0xe4, 0xf4, 0x52, 0x9b, 0x7e, 0x87, 0x6a,
		//0x72, 0x26, 0x3a, 0xac, 0x01, 0xce, 0x5b, 0x08, 0x46, 0x1d, 0xf9, 0x96, 0x61, 0xa0, 0xfb, 0xb1,
		//0xf4, 0xa3, 0x40, 0x3e, 0xe3, 0xfe, 0x0f, 0x01,
		0x30, 0x45, 0x02, 0x21, 0x00, 0x92, 0x55, 0x86, 0x37, 0x0e, 0x5a, 0x32,
		0x8a, 0x96, 0xa1, 0x45, 0xaf, 0xca, 0x61, 0xa3, 0xbb, 0xb4, 0x6c, 0x58,
		0x41, 0x3e, 0x7a, 0x01, 0x2f, 0xfb, 0xf9, 0x29, 0xc0, 0xfd, 0x44, 0x9b,
		0xc2, 0x02, 0x20, 0x60, 0x38, 0xdb, 0x15, 0x6c, 0xfb, 0xb3, 0x16, 0xb3,
		0xce, 0x14, 0xcc, 0xa4, 0xe3, 0x92, 0x5a, 0xa3, 0x0e, 0x81, 0xcf, 0x24,
		0x18, 0x94, 0x42, 0x23, 0x3b, 0x7b, 0x1f, 0x2a, 0xdf, 0x09, 0xb9, 0x01,
	}, {
		0x21, 0x03, 0xcc, 0xb9, 0xdd, 0xe8, 0xcd, 0x8e, 0x42, 0x36, 0xe3, 0xb4, 0x44, 0xdd, 0x92, 0x62,
		0xaf, 0x43, 0xb0, 0x2d, 0xd9, 0x5a, 0x8e, 0xf3, 0x36, 0xea, 0xf4, 0xca, 0xca, 0x75, 0x6c, 0xf4,
		0x88, 0xe1, 0xad, 0x21, 0x03, 0xa4, 0x12, 0x0a, 0x06, 0xdb, 0x34, 0x62, 0xc9, 0xee, 0xd7, 0x5e,
		0x27, 0xf4, 0x5c, 0x66, 0x40, 0x68, 0xd4, 0x6c, 0xbb, 0x68, 0x5e, 0xa9, 0x2a, 0xfc, 0x3e, 0xc5,
		0x3e, 0x40, 0x1e, 0xf1, 0xe1, 0xac, 0x73, 0x64, 0x03, 0x27, 0x18, 0x0b, 0xb1, 0x68,
		//  0x21, 0x03, 0xcc, 0xb9, 0xdd, 0xe8, 0xcd, 0x8e, 0x42, 0x36, 0xe3, 0xb4, 0x44, 0xdd, 0x92, 0x62,
		//  0xaf, 0x43, 0xb0, 0x2d, 0xd9, 0x5a, 0x8e, 0xf3, 0x36, 0xea, 0xf4, 0xca, 0xca, 0x75, 0x6c, 0xf4,
		//  0x88, 0xe1, 0xad, 0x21, 0x03, 0xa4, 0x12, 0x0a, 0x06, 0xdb, 0x34, 0x62, 0xc9, 0xee, 0xd7, 0x5e,
		//  0x27, 0xf4, 0x5c, 0x66, 0x40, 0x68, 0xd4, 0x6c, 0xbb, 0x68, 0x5e, 0xa9, 0x2a, 0xfc, 0x3e, 0xc5,
		//  0x3e, 0x40, 0x1e, 0xf1, 0xe1, 0xac, 0x73, 0x64, 0x03, 0x27, 0x18, 0x0b, 0xb1, 0x68
	}}

	txOut := &wire.TxOut{
		Value: 2999859,
		PkScript: []byte{
			0x00, 0x14, 0x5a, 0x03, 0x54, 0x00, 0x52, 0x28, 0xa7, 0x68, 0xdb, 0xf5, 0x08, 0x42, 0x1d,
			0x99, 0x0d, 0xde, 0xe5, 0x16, 0x18, 0xd9,
		},
	}

	prevOutPkScript, _ := hex.DecodeString("002081cd5acc478ffa7590999265763b7fe4a66e66b5cfe79030ac0a3174cbfaa967")

	pubKey1Bytes, _ := hex.DecodeString("03ccb9dde8cd8e4236e3b444dd9262af43b02dd95a8ef336eaf4caca756cf488e1")
	pubKey1, _ := btcec.ParsePubKey(pubKey1Bytes, btcec.S256())
	fmt.Printf("Key 1: %x\n", pubKey1.SerializeCompressed())

	pubKey2Bytes, _ := hex.DecodeString("03a4120a06db3462c9eed75e27f45c664068d46cbb685ea92afc3ec53e401ef1e1")
	pubKey2, _ := btcec.ParsePubKey(pubKey2Bytes, btcec.S256())
	fmt.Printf("Key 2: %x\n", pubKey2.SerializeCompressed())

	auctioneerKeyBytes, _ := hex.DecodeString("028e87bdd134238f8347f845d9ecc827b843d0d1e27cdcb46da704d916613f4fce")
	auctioneerKey, _ := btcec.ParsePubKey(auctioneerKeyBytes, btcec.S256())

	traderKeyBytes, _ := hex.DecodeString("0288c2f634fda9710fe1da3859f79d47b04bd76aed39258cd2a88c9213cd1ffa62")
	traderKey, _ := btcec.ParsePubKey(traderKeyBytes, btcec.S256())

	batchKeyBytes, _ := hex.DecodeString("023c83266908876329b7914434d96991b83ac57621dbbc8de4a3f228caff83e39e")
	batchKey, _ := btcec.ParsePubKey(batchKeyBytes, btcec.S256())

	// keyTweakBytes, _ := hex.DecodeString("81094896692dd5df33c294ad459c8e58d862c6c0a97f061590b2490c3686958a")
	sharedKeyBytes, _ := hex.DecodeString("8c68279d2a92d5e667848bba48c260c57077eb633d43bfd3ad08af250845e38f")

	var sharedKey [32]byte
	copy(sharedKey[:], sharedKeyBytes)

	accountScript, err := AccountScript(727079, traderKey, auctioneerKey, batchKey, sharedKey)
	require.NoError(t, err)
	require.Equal(t, prevOutPkScript, accountScript)

	tx := &wire.MsgTx{
		Version: 2,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *opHash,
				Index: 1,
			},
			Witness: witness,
		}},
		TxOut: []*wire.TxOut{txOut},
	}

	txHash := tx.TxHash()
	require.Equal(t, "3d60e4f82e3db01de5e1975a068d975358e86192e801becd67ec35b115e31f3a", txHash.String())

	sigHash, err := txscript.CalcWitnessSigHash(
		witness[2], txscript.NewTxSigHashes(tx), txscript.SigHashAll,
		tx, 0, txOut.Value,
	)
	require.NoError(t, err)

	script, err := txscript.DisasmString(witness[2])
	require.NoError(t, err)

	fmt.Printf("Script: %s\n", script)

	sig1Bytes := witness[0][0 : len(witness[0])-1]
	fmt.Printf("Sig1: %x\n", sig1Bytes)
	sig2Bytes := witness[1][0 : len(witness[1])-1]
	fmt.Printf("Sig2: %x\n", sig2Bytes)

	sig1, err := btcec.ParseDERSignature(sig1Bytes, btcec.S256())
	require.NoError(t, err)

	sig2, err := btcec.ParseDERSignature(sig2Bytes, btcec.S256())
	require.NoError(t, err)

	fmt.Printf("Sig 1 R: %x, S: %x\n", sig1.R.Bytes(), sig1.S.Bytes())
	fmt.Printf("Sig 2 R: %x, S: %x\n", sig2.R.Bytes(), sig2.S.Bytes())

	fmt.Printf("Sig 1 key 1: %v\n", sig1.Verify(sigHash, pubKey1))
	fmt.Printf("Sig 1 key 2: %v\n", sig1.Verify(sigHash, pubKey2))
	fmt.Printf("Sig 2 key 1: %v\n", sig2.Verify(sigHash, pubKey1))
	fmt.Printf("Sig 2 key 2: %v\n", sig2.Verify(sigHash, pubKey2))

	assertEngineExecution(t, 0, true, func() (*txscript.Engine, error) {
		return txscript.NewEngine(
			prevOutPkScript, tx, 0, txscript.StandardVerifyFlags,
			nil, nil, txOut.Value,
		)
	})
}

// assertEngineExecution executes the VM returned by the newEngine closure,
// asserting the result matches the validity expectation. In the case where it
// doesn't match the expectation, it executes the script step-by-step and
// prints debug information to stdout.
func assertEngineExecution(t *testing.T, testNum int, valid bool,
	newEngine func() (*txscript.Engine, error)) {
	t.Helper()

	// Get a new VM to execute.
	vm, err := newEngine()
	if err != nil {
		t.Fatalf("unable to create engine: %v", err)
	}

	// Execute the VM, only go on to the step-by-step execution if
	// it doesn't validate as expected.
	vmErr := vm.Execute()
	if valid == (vmErr == nil) {
		return
	}

	// Now that the execution didn't match what we expected, fetch a new VM
	// to step through.
	vm, err = newEngine()
	if err != nil {
		t.Fatalf("unable to create engine: %v", err)
	}

	// This buffer will trace execution of the Script, dumping out
	// to stdout.
	var debugBuf bytes.Buffer

	done := false
	for !done {
		dis, err := vm.DisasmPC()
		if err != nil {
			t.Fatalf("stepping (%v)\n", err)
		}
		debugBuf.WriteString(fmt.Sprintf("stepping %v\n", dis))

		done, err = vm.Step()
		if err != nil && valid {
			fmt.Println(debugBuf.String())
			t.Fatalf("spend test case #%v failed, spend "+
				"should be valid: %v", testNum, err)
		} else if err == nil && !valid && done {
			fmt.Println(debugBuf.String())
			t.Fatalf("spend test case #%v succeed, spend "+
				"should be invalid: %v", testNum, err)
		}

		debugBuf.WriteString(fmt.Sprintf("Stack: %v", vm.GetStack()))
		debugBuf.WriteString(fmt.Sprintf("AltStack: %v", vm.GetAltStack()))
	}

	// If we get to this point the unexpected case was not reached
	// during step execution, which happens for some checks, like
	// the clean-stack rule.
	validity := "invalid"
	if valid {
		validity = "valid"
	}

	fmt.Println(debugBuf.String())
	t.Fatalf("%v spend test case #%v execution ended with: %v", validity, testNum, vmErr)
}

// TestIncrementDecrementKey makes sure that incrementing and decrementing an EC
// public key are inverse operations to each other.
func TestIncrementDecrementKey(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(t, err)

	randomStartBatchKey := privKey.PubKey()

	// Increment the key numOperations times.
	currentKey := randomStartBatchKey
	for i := 0; i < numOperations; i++ {
		currentKey = IncrementKey(currentKey)
	}

	// Decrement the key again.
	for i := 0; i < numOperations; i++ {
		currentKey = DecrementKey(currentKey)
	}

	// We should arrive at the same start key again.
	require.Equal(t, randomStartBatchKey, currentKey)
}
