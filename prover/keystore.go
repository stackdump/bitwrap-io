package prover

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/rs/zerolog/log"
)

// KeyStore manages persistent storage of compiled circuit keys.
type KeyStore struct {
	dir string
}

// NewKeyStore creates a key store at the given directory.
func NewKeyStore(dir string) (*KeyStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create keystore dir: %w", err)
	}
	return &KeyStore{dir: dir}, nil
}

// Has returns true if keys exist for the named circuit.
func (ks *KeyStore) Has(name string) bool {
	_, err := os.Stat(ks.pkPath(name))
	return err == nil
}

// Save writes a compiled circuit's keys to disk.
func (ks *KeyStore) Save(name string, cc *CompiledCircuit) error {
	// Save constraint system
	{
		f, err := os.Create(ks.csPath(name))
		if err != nil {
			return fmt.Errorf("save cs %s: %w", name, err)
		}
		if _, err := cc.CS.WriteTo(f); err != nil {
			f.Close()
			return fmt.Errorf("write cs %s: %w", name, err)
		}
		f.Close()
	}

	// Save proving key
	{
		f, err := os.Create(ks.pkPath(name))
		if err != nil {
			return fmt.Errorf("save pk %s: %w", name, err)
		}
		if _, err := cc.ProvingKey.WriteTo(f); err != nil {
			f.Close()
			return fmt.Errorf("write pk %s: %w", name, err)
		}
		f.Close()
	}

	// Save verifying key
	{
		f, err := os.Create(ks.vkPath(name))
		if err != nil {
			return fmt.Errorf("save vk %s: %w", name, err)
		}
		if _, err := cc.VerifyingKey.WriteTo(f); err != nil {
			f.Close()
			return fmt.Errorf("write vk %s: %w", name, err)
		}
		f.Close()
	}

	log.Debug().Str("circuit", name).Str("dir", ks.dir).Msg("Keys saved")
	return nil
}

// Load reads a compiled circuit's keys from disk.
func (ks *KeyStore) Load(name string) (*CompiledCircuit, error) {
	cs := groth16.NewCS(ecc.BN254)
	{
		f, err := os.Open(ks.csPath(name))
		if err != nil {
			return nil, fmt.Errorf("load cs %s: %w", name, err)
		}
		if _, err := cs.ReadFrom(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("read cs %s: %w", name, err)
		}
		f.Close()
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	{
		f, err := os.Open(ks.pkPath(name))
		if err != nil {
			return nil, fmt.Errorf("load pk %s: %w", name, err)
		}
		if _, err := pk.ReadFrom(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("read pk %s: %w", name, err)
		}
		f.Close()
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	{
		f, err := os.Open(ks.vkPath(name))
		if err != nil {
			return nil, fmt.Errorf("load vk %s: %w", name, err)
		}
		if _, err := vk.ReadFrom(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("read vk %s: %w", name, err)
		}
		f.Close()
	}

	return &CompiledCircuit{
		Name:         name,
		CS:           cs,
		ProvingKey:   pk,
		VerifyingKey: vk,
		Constraints:  cs.GetNbConstraints(),
		PublicVars:   cs.GetNbPublicVariables(),
		PrivateVars:  cs.GetNbSecretVariables(),
	}, nil
}

// CompileAndSave compiles a circuit and persists the keys.
// If keys already exist on disk, loads them instead (skipping compilation).
func (ks *KeyStore) CompileAndSave(p *Prover, name string, circuit frontend.Circuit) (*CompiledCircuit, error) {
	if ks.Has(name) {
		log.Debug().Str("circuit", name).Msg("Loading cached keys")
		return ks.Load(name)
	}

	log.Debug().Str("circuit", name).Msg("Compiling circuit (no cached keys)")
	cc, err := p.CompileCircuit(name, circuit)
	if err != nil {
		return nil, err
	}

	if err := ks.Save(name, cc); err != nil {
		log.Warn().Err(err).Str("circuit", name).Msg("Failed to save keys (will recompile next time)")
	}

	return cc, nil
}

// ExportVerifyingKey returns the raw bytes of a verifying key.
func (ks *KeyStore) ExportVerifyingKey(name string) ([]byte, error) {
	return os.ReadFile(ks.vkPath(name))
}

// ExportSolidityVerifier generates a Solidity verifier contract for a circuit.
func (ks *KeyStore) ExportSolidityVerifier(name string) ([]byte, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, err := os.Open(ks.vkPath(name))
	if err != nil {
		return nil, fmt.Errorf("load vk %s: %w", name, err)
	}
	if _, err := vk.ReadFrom(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("read vk %s: %w", name, err)
	}
	f.Close()

	var buf bytes.Buffer
	if err := vk.ExportSolidity(&buf); err != nil {
		return nil, fmt.Errorf("export solidity verifier %s: %w", name, err)
	}
	return buf.Bytes(), nil
}

// Purge removes all cached keys for a circuit (forces recompilation).
func (ks *KeyStore) Purge(name string) error {
	for _, path := range []string{ks.csPath(name), ks.pkPath(name), ks.vkPath(name)} {
		os.Remove(path)
	}
	log.Debug().Str("circuit", name).Msg("Keys purged")
	return nil
}

// PurgeAll removes all cached keys.
func (ks *KeyStore) PurgeAll() error {
	entries, err := os.ReadDir(ks.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		os.Remove(filepath.Join(ks.dir, e.Name()))
	}
	log.Debug().Str("dir", ks.dir).Msg("All keys purged")
	return nil
}

// RegisterWithKeyStore compiles circuits using the key store for caching.
func RegisterWithKeyStore(p *Prover, ks *KeyStore, circuits map[string]frontend.Circuit) error {
	for name, circuit := range circuits {
		cc, err := ks.CompileAndSave(p, name, circuit)
		if err != nil {
			return fmt.Errorf("circuit %s: %w", name, err)
		}
		p.StoreCircuit(name, cc)
	}
	return nil
}

// Path helpers

func (ks *KeyStore) csPath(name string) string {
	return filepath.Join(ks.dir, name+".cs")
}

func (ks *KeyStore) pkPath(name string) string {
	return filepath.Join(ks.dir, name+".pk")
}

func (ks *KeyStore) vkPath(name string) string {
	return filepath.Join(ks.dir, name+".vk")
}
