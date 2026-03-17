package prover

import (
	"github.com/consensys/gnark/backend"
	goprover "github.com/pflow-xyz/go-pflow/prover"
)

// Re-export types from go-pflow/prover so consumers keep using prover.X.

// Core prover types.
type Prover = goprover.Prover
type CompiledCircuit = goprover.CompiledCircuit
type ProofResult = goprover.ProofResult
type ProofJob = goprover.ProofJob
type ProofJobResult = goprover.ProofJobResult
type ProofPool = goprover.ProofPool

// Service types.
type Service = goprover.Service
type WitnessFactory = goprover.WitnessFactory
type HealthResponse = goprover.HealthResponse
type CircuitInfo = goprover.CircuitInfo
type CircuitListResponse = goprover.CircuitListResponse
type ProveRequest = goprover.ProveRequest
type ProveResponse = goprover.ProveResponse

// Curve types.
type CurveConfig = goprover.CurveConfig
type CurveRole = goprover.CurveRole
type CurveProver = goprover.CurveProver
type CurveCompiledCircuit = goprover.CurveCompiledCircuit
type CurveProofResult = goprover.CurveProofResult
type RecursionStack = goprover.RecursionStack

// Aggregator types.
type AggregatorCircuit = goprover.AggregatorCircuit
type AggregatorWitness = goprover.AggregatorWitness
type AggregatedBatchProof = goprover.AggregatedBatchProof
type InnerBatchCircuit = goprover.InnerBatchCircuit

// Wrapper types.
type WrapperCircuit = goprover.WrapperCircuit
type WrapperWitness = goprover.WrapperWitness
type WrappedProof = goprover.WrappedProof
type AggregationPlaceholderCircuit = goprover.AggregationPlaceholderCircuit

// Pipeline types.
type AggregationPipeline = goprover.AggregationPipeline
type InnerProofResult = goprover.InnerProofResult
type PipelineConfig = goprover.PipelineConfig
type BatchMetadata = goprover.BatchMetadata

// Re-export functions.
var NewProver = goprover.NewProver
var NewProofPool = goprover.NewProofPool
var NewService = goprover.NewService
var GetCircuitInfo = goprover.GetCircuitInfo
var ParseBigInt = goprover.ParseBigInt
var ParseWitnessField = goprover.ParseWitnessField
var NewCurveProver = goprover.NewCurveProver
var NewRecursionStack = goprover.NewRecursionStack
var CompileInnerPlaceholder = goprover.CompileInnerPlaceholder
var NewAggregatorCircuit = goprover.NewAggregatorCircuit
var RegisterAggregatorCircuit = goprover.RegisterAggregatorCircuit
var CompileAggregationPlaceholder = goprover.CompileAggregationPlaceholder
var NewWrapperCircuit = goprover.NewWrapperCircuit
var RegisterWrapperCircuit = goprover.RegisterWrapperCircuit
var DefaultPipelineConfig = goprover.DefaultPipelineConfig
var NewAggregationPipeline = goprover.NewAggregationPipeline

// Re-export constants.
const DefaultAggregationSize = goprover.DefaultAggregationSize

// Re-export curve role constants.
const (
	RoleInner       = goprover.RoleInner
	RoleAggregation = goprover.RoleAggregation
	RoleWrapper     = goprover.RoleWrapper
)

// Re-export curve config variables.
var (
	BN254Config     = goprover.BN254Config
	BLS12_377Config = goprover.BLS12_377Config
	BW6_761Config   = goprover.BW6_761Config
)

// Re-export backend option functions.
// These return interface types, so we wrap them.

func GetNativeProverOptions() backend.ProverOption {
	return goprover.GetNativeProverOptions()
}

func GetNativeVerifierOptions() backend.VerifierOption {
	return goprover.GetNativeVerifierOptions()
}

func GetWrapperProverOptions() backend.ProverOption {
	return goprover.GetWrapperProverOptions()
}

func GetWrapperVerifierOptions() backend.VerifierOption {
	return goprover.GetWrapperVerifierOptions()
}
