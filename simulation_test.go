package nmt_test

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
	"github.com/tidwall/gjson"
)

func getLeavesFromState(state gjson.Result, nidSize int) [][]byte {
	itf_leaves := state.Get("leaves_v").Array()
	var leaves [][]byte

	for _, itf_leaf := range itf_leaves {
		stateNamespace := int(itf_leaf.Get("namespaceId").Int())

		namespaceBytes := intToBytes(stateNamespace, nidSize)

		data := make([]byte, 8)
		dataString := itf_leaf.Get("value.#tup.1").String()
		fmt.Printf("namespace is %v, data is %v\n", stateNamespace, dataString)
		copy(data, []byte(dataString))
		pushData := namespace.PrefixedData(append(namespaceBytes, data...))
		leaves = append(leaves, pushData)

	}
	return leaves
}

func checkProof(modelProof gjson.Result, execProof nmt.Proof, nidSize int) bool {
	modelProofStart := int(modelProof.Get("start").Int())
	execProofStart := execProof.Start()

	modelProofEnd := int(modelProof.Get("end").Int())
	execProofEnd := execProof.End()
	if modelProofStart != execProofStart || modelProofEnd != execProofEnd {
		return false
	}
	supporting_hashes := modelProof.Get("supporting_hashes").Array()
	if len(supporting_hashes) != len(execProof.Nodes()) {
		return false
	}
	for idx, supporting_hash := range supporting_hashes {
		modelMinNS := int(supporting_hash.Get("minNS").Int())
		execMinNs := bytesToInt(execProof.Nodes()[idx][:nidSize])
		if modelMinNS != execMinNs {
			return false
		}

		modelMaxNS := int(supporting_hash.Get("maxNS").Int())
		execMaxNs := bytesToInt(execProof.Nodes()[idx][nidSize:(2 * nidSize)])
		if modelMaxNS != execMaxNs {
			return false
		}
	}

	return true

}

func intToBytes(n int, nidSize int) []byte {
	b := make([]byte, nidSize)
	for i := 0; i < nidSize; i++ {
		b[i] = byte(n >> (8 * (nidSize - i - 1)))
	}
	return b
}

func bytesToInt(bytes []byte) int {
	var result int
	for i, b := range bytes {
		shift := uint((len(bytes) - 1 - i) * 8)
		result |= int(b) << shift
	}
	return result
}

func TestFromITF(t *testing.T) {

	var tree *nmt.NamespacedMerkleTree
	nidSize := 1

	itfFileName := "ITF_files/run.itf.json"
	data, err := ioutil.ReadFile(itfFileName)
	if err != nil {
		t.Errorf("Error opening file: %v", err)
	}
	states := gjson.GetBytes(data, "states").Array()

	// iterate over all states of the protocol run
	for _, state := range states {

		// check only the finaly state
		if state.Get("last_state_v").String() == "final" {
			stateNamespace := state.Get("namespace_v").Int()
			leaves := getLeavesFromState(state, nidSize)
			proofPassesVerification := state.Get("verification_success_v").Bool()
			t.Logf("Obtained state data:\n\tState namespace: %v\n\tleaves: %v\n\tshouldPass: %v\n",
				stateNamespace, leaves, proofPassesVerification)

			tree = nmt.New(sha256.New(), nmt.NamespaceIDSize(nidSize))
			for idx, leaf := range leaves {
				fmt.Printf("leaf %v: %v\n", idx, leaf)
				err := tree.Push(leaf)
				if err != nil {
					t.Errorf("Error on push: %v", err)
				}
			}

			namespaceBytes := intToBytes(int(stateNamespace), nidSize)

			proof, err := tree.ProveNamespace(namespaceBytes)
			if err != nil {
				t.Errorf("Error on prove: %v", err)
			}
			t.Logf("Proof: %v\n", proof)
			modelProof := state.Get("proof_v")
			proofMatching := checkProof(modelProof, proof, nidSize)
			if !proofMatching {
				t.Errorf("Proofs do not match. Expected: %v, got: %v", state, proof)
			}

			root, _ := tree.Root()

			// namespaceBytes := make([]byte, nidSize)

			// binary.LittleEndian.PutUint64(namespaceBytes, uint64(stateNamespace))

			// TODO: this is now data from the three. Modify to take it from the state (will be better for non-happy paths)
			// dataToVerify := tree.Get(namespaceBytes)
			dataToVerify := leaves[proof.Start():proof.End()]

			fmt.Printf("Verifying. Root: %v, Namespace: %x, Leaves: %v, Proof: %v\n", root, namespaceBytes, dataToVerify, proof)

			successVerification := proof.VerifyNamespace(sha256.New(), namespaceBytes, dataToVerify, root)
			fmt.Printf("Verification result: %v\n", successVerification)

			if successVerification != proofPassesVerification {
				t.Errorf("Mismatch between expected verification result %v and actual verification result %v\b", proofPassesVerification, successVerification)
			}

		} else {
			continue
		}

	}
	// t.Fail()

}
