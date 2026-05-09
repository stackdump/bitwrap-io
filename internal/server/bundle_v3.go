package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (s *Server) handleBundleVoteV3(w http.ResponseWriter, _ *http.Request) {
	if s.keyStore == nil {
		http.Error(w, "Key store not enabled (start with -key-dir flag)", http.StatusServiceUnavailable)
		return
	}

	voteCircuit := "voteCastHomomorphic_8"
	tallyCircuit := "tallyDecrypt_8"
	if !s.keyStore.Has(voteCircuit) || !s.keyStore.Has(tallyCircuit) {
		http.Error(w, "v3 verifier keys not available (need voteCastHomomorphic_8 + tallyDecrypt_8)", http.StatusServiceUnavailable)
		return
	}

	voteVerifier, err := s.keyStore.ExportSolidityVerifier(voteCircuit)
	if err != nil {
		http.Error(w, fmt.Sprintf("export %s verifier: %v", voteCircuit, err), http.StatusInternalServerError)
		return
	}
	tallyVerifier, err := s.keyStore.ExportSolidityVerifier(tallyCircuit)
	if err != nil {
		http.Error(w, fmt.Sprintf("export %s verifier: %v", tallyCircuit, err), http.StatusInternalServerError)
		return
	}
	voteVerifierSol, err := renameVerifierContract(string(voteVerifier), "Verifier_voteCastHomomorphic_8")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tallyVerifierSol, err := renameVerifierContract(string(tallyVerifier), "Verifier_tallyDecrypt_8")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	files := map[string]string{
		"foundry.toml":                           v3FoundryToml,
		"src/BitwrapZKPollV3.sol":                v3PollContract,
		"src/Verifier_voteCastHomomorphic_8.sol": voteVerifierSol,
		"src/Verifier_tallyDecrypt_8.sol":        tallyVerifierSol,
		"test/BitwrapZKPollV3.t.sol":             v3FoundryTest,
		"script/DeployV3.s.sol":                  v3DeployScript,
		"README.md":                              v3BundleREADME,
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			log.Printf("bundle-v3: failed to create zip entry %s: %v", name, err)
			http.Error(w, "failed to create bundle entry", http.StatusInternalServerError)
			return
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			log.Printf("bundle-v3: failed to write zip entry %s: %v", name, err)
			http.Error(w, "failed to write bundle entry", http.StatusInternalServerError)
			return
		}
	}
	if err := zw.Close(); err != nil {
		log.Printf("bundle-v3: failed to finalize zip: %v", err)
		http.Error(w, "failed to finalize bundle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=BitwrapZKPollV3.zip")
	_, _ = w.Write(zipBuf.Bytes())
}

func renameVerifierContract(soliditySource, contractName string) (string, error) {
	const oldDecl = "contract Verifier {"
	if !strings.Contains(soliditySource, oldDecl) {
		return "", fmt.Errorf("unexpected verifier format: contract declaration not found")
	}
	return strings.Replace(soliditySource, oldDecl, "contract "+contractName+" {", 1), nil
}

const v3FoundryToml = `[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"

[fmt]
line_length = 120
`

const v3PollContract = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifierVoteCastHomomorphic8 {
    function verifyProof(uint256[8] calldata proof, uint256[38] calldata input) external view;
}

interface IVerifierTallyDecrypt8 {
    function verifyProof(uint256[8] calldata proof, uint256[42] calldata input) external view;
}

contract BitwrapZKPollV3 {
    struct Ciphertext {
        uint256 ax;
        uint256 ay;
        uint256 bx;
        uint256 by;
    }

    address public immutable owner;
    uint256[2] public pkCreator;
    IVerifierVoteCastHomomorphic8 public voteVerifier;
    IVerifierTallyDecrypt8 public tallyVerifier;

    Ciphertext[8] public aggregateCiphertexts;
    uint256[8] public settledTallies;
    bool public tallyArtifactSet;
    bool public settled;

    event AggregateStored(uint256 indexed ballotCount);
    event PollSettled(uint256[8] tallies);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(
        uint256[2] memory _pkCreator,
        address _voteVerifier,
        address _tallyVerifier
    ) {
        owner = msg.sender;
        pkCreator = _pkCreator;
        voteVerifier = IVerifierVoteCastHomomorphic8(_voteVerifier);
        tallyVerifier = IVerifierTallyDecrypt8(_tallyVerifier);
    }

    function setAggregateCiphertexts(Ciphertext[8] calldata aggregate, uint256 ballotCount) external onlyOwner {
        require(!settled, "already settled");
        aggregateCiphertexts = aggregate;
        tallyArtifactSet = true;
        emit AggregateStored(ballotCount);
    }

    function verifyCastVoteProof(
        uint256[8] calldata proof,
        uint256[38] calldata input
    ) external view returns (bool) {
        try voteVerifier.verifyProof(proof, input) {
            return true;
        } catch {
            return false;
        }
    }

    function verifyTallyDecryptProof(
        uint256[8] calldata proof,
        uint256[8] calldata tallies
    ) public view returns (bool) {
        if (!tallyArtifactSet) {
            return false;
        }

        // gnark walks the circuit struct depth-first in declaration order:
        // PkCreator{X,Y}, A[0..7]{X,Y} as one block, then B[0..7]{X,Y}
        // as the next, then Tallies[0..7]. Feeding (A,B) interleaved
        // per-index would land the public-input MSM at the wrong group
        // element and verifyProof would always revert with ProofInvalid().
        uint256[42] memory input;
        input[0] = pkCreator[0];
        input[1] = pkCreator[1];

        uint256 idx = 2;
        for (uint256 i = 0; i < 8; i++) {
            Ciphertext memory ct = aggregateCiphertexts[i];
            input[idx++] = ct.ax;
            input[idx++] = ct.ay;
        }
        for (uint256 i = 0; i < 8; i++) {
            Ciphertext memory ct = aggregateCiphertexts[i];
            input[idx++] = ct.bx;
            input[idx++] = ct.by;
        }
        for (uint256 i = 0; i < 8; i++) {
            input[idx++] = tallies[i];
        }

        try tallyVerifier.verifyProof(proof, input) {
            return true;
        } catch {
            return false;
        }
    }

    function closePollV3(uint256[8] calldata decryptProof, uint256[8] calldata tallies) external onlyOwner {
        require(!settled, "already settled");
        require(tallyArtifactSet, "aggregate not set");
        require(verifyTallyDecryptProof(decryptProof, tallies), "invalid decrypt proof");

        settledTallies = tallies;
        settled = true;

        emit PollSettled(tallies);
    }
}
`

const v3FoundryTest = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {BitwrapZKPollV3} from "../src/BitwrapZKPollV3.sol";

contract MockVoteVerifier {
    bool internal _valid = true;

    function setValid(bool valid) external {
        _valid = valid;
    }

    function verifyProof(uint256[8] calldata, uint256[38] calldata) external view {
        require(_valid, "invalid vote proof");
    }
}

contract MockTallyVerifier {
    bool internal _valid = true;

    function setValid(bool valid) external {
        _valid = valid;
    }

    function verifyProof(uint256[8] calldata, uint256[42] calldata) external view {
        require(_valid, "invalid tally proof");
    }
}

contract BitwrapZKPollV3Test is Test {
    BitwrapZKPollV3 poll;
    MockVoteVerifier voteVerifier;
    MockTallyVerifier tallyVerifier;

    function setUp() public {
        voteVerifier = new MockVoteVerifier();
        tallyVerifier = new MockTallyVerifier();
        poll = new BitwrapZKPollV3([uint256(1), uint256(2)], address(voteVerifier), address(tallyVerifier));
    }

    function testVerifyCastVoteProof() public {
        uint256[8] memory proof;
        uint256[38] memory input;
        assertTrue(poll.verifyCastVoteProof(proof, input));
    }

    function testClosePollV3() public {
        BitwrapZKPollV3.Ciphertext[8] memory aggregate;
        uint256[8] memory proof;
        uint256[8] memory tallies;
        tallies[0] = 2;
        tallies[1] = 1;

        poll.setAggregateCiphertexts(aggregate, 3);
        poll.closePollV3(proof, tallies);

        assertTrue(poll.settled());
        assertEq(poll.settledTallies(0), 2);
        assertEq(poll.settledTallies(1), 1);
    }
}
`

const v3DeployScript = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {BitwrapZKPollV3} from "../src/BitwrapZKPollV3.sol";
import {Verifier_voteCastHomomorphic_8} from "../src/Verifier_voteCastHomomorphic_8.sol";
import {Verifier_tallyDecrypt_8} from "../src/Verifier_tallyDecrypt_8.sol";

contract DeployV3 is Script {
    function run() external {
        vm.startBroadcast();

        Verifier_voteCastHomomorphic_8 voteVerifier = new Verifier_voteCastHomomorphic_8();
        Verifier_tallyDecrypt_8 tallyVerifier = new Verifier_tallyDecrypt_8();

        // Replace with the real creator public key coordinates before broadcast.
        uint256[2] memory pkCreator = [uint256(0), uint256(0)];
        new BitwrapZKPollV3(pkCreator, address(voteVerifier), address(tallyVerifier));

        vm.stopBroadcast();
    }
}
`

const v3BundleREADME = `# BitwrapZKPollV3 Foundry Bundle

This bundle contains an on-chain settlement loop for vote schema v3 (homomorphic tally):

- src/BitwrapZKPollV3.sol — v3 governance contract with settlement flow.
- src/Verifier_voteCastHomomorphic_8.sol — Groth16 verifier for per-vote proofs.
- src/Verifier_tallyDecrypt_8.sol — Groth16 verifier for close-time decrypt proofs.
- test/BitwrapZKPollV3.t.sol — harness test for proof verification wiring + settlement.
- script/DeployV3.s.sol — deployment script for local/anvil or production chains.

## Quick start

` + "```bash" + `
git init
forge install foundry-rs/forge-std
forge build
forge test -vv
` + "```" + `
`
