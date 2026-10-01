package emulator

import (
	"github.com/isesword/golem/internal/arch"
)

// Public Semantic API — values. A Value carries an integer with its ABI
// KIND, so callers stop caring whether "a 64-bit argument" is one register
// (ARM64), an even register pair (ARM32), or stack spill slot #6 (AMD64).
// The kind is interpreted by the CallABI at the boundary; on the public
// surface it only makes intent explicit and portable.

// ValueKind classifies an argument/return value by its ABI kind.
type ValueKind uint8

const (
	// Word is one machine word of the TARGET's natural width (u32 on
	// ARM32, u64 on ARM64/AMD64) — the default for plain integer args.
	Word ValueKind = iota
	// Pointer is a guest pointer (word-width, pointer semantics).
	Pointer
	// U32 is an unsigned 32-bit integer.
	U32
	// I32 is a signed 32-bit integer.
	I32
	// U64 is an unsigned 64-bit integer (register pair on 32-bit ABIs).
	U64
	// I64 is a signed 64-bit integer (register pair on 32-bit ABIs).
	I64
)

func (k ValueKind) String() string {
	switch k {
	case Word:
		return "word"
	case Pointer:
		return "ptr"
	case U32:
		return "u32"
	case I32:
		return "i32"
	case U64:
		return "u64"
	case I64:
		return "i64"
	default:
		return "value"
	}
}

// Value is one typed integer crossing the guest ABI boundary.
type Value struct {
	Kind ValueKind
	Raw  uint64
}

// Uint64 returns the value as uint64 (the raw bits).
func (v Value) Uint64() uint64 { return v.Raw }

// Int64 returns the value as int64 (reinterpreting the raw bits).
func (v Value) Int64() int64 { return int64(v.Raw) }

// Uint32 returns the low 32 bits as uint32.
func (v Value) Uint32() uint32 { return uint32(v.Raw) }

// Int32 returns the low 32 bits as int32 (reinterpreting the raw bits).
func (v Value) Int32() int32 { return int32(v.Raw) }

// Ptr builds a guest-pointer Value.
func Ptr(addr uint64) Value { return Value{Kind: Pointer, Raw: addr} }

// Uint32 builds an unsigned 32-bit Value.
func Uint32(v uint32) Value { return Value{Kind: U32, Raw: uint64(v)} }

// Int32 builds a signed 32-bit Value.
func Int32(v int32) Value { return Value{Kind: I32, Raw: uint64(uint32(v))} }

// Uint64 builds an unsigned 64-bit Value.
func Uint64(v uint64) Value { return Value{Kind: U64, Raw: v} }

// Int64 builds a signed 64-bit Value.
func Int64(v int64) Value { return Value{Kind: I64, Raw: uint64(v)} }

// callArg maps a Value onto the arch-level typed argument (Advanced layer):
// word-class kinds collapse to ArgWord, 64-bit kinds to their pair form.
func (v Value) callArg() arch.CallArg {
	switch v.Kind {
	case U64:
		return arch.CallArg{Value: v.Raw, Kind: arch.ArgU64}
	case I64:
		return arch.CallArg{Value: v.Raw, Kind: arch.ArgI64}
	default: // Word / Pointer / U32 / I32: one slot, natural width
		return arch.CallArg{Value: v.Raw, Kind: arch.ArgWord}
	}
}

func valuesToCallArgs(vs []Value) []arch.CallArg {
	out := make([]arch.CallArg, len(vs))
	for i, v := range vs {
		out[i] = v.callArg()
	}
	return out
}

// Words builds word-kind Values — the DEFAULT for plain integer arguments:
// one machine word each (on 32-bit targets one register, never a pair).
// For genuinely 64-bit values on 32-bit ABIs use Uint64/Int64 (register
// pair), and Ptr for pointers.
func Words(vs ...uint64) []Value {
	out := make([]Value, len(vs))
	for i, v := range vs {
		out[i] = Value{Kind: Word, Raw: v}
	}
	return out
}
