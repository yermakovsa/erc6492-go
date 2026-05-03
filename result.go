package erc6492

// Result is the outcome of a signature verification attempt.
type Result struct {
	Valid  bool
	Method Method
}

// Method identifies the verification method that produced a Result.
type Method string

const (
	MethodUnknown Method = "unknown"
	MethodEOA     Method = "eoa"
	MethodEIP1271 Method = "eip1271"
	MethodERC6492 Method = "erc6492"
)
