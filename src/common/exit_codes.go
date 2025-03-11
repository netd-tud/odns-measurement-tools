package common

type ExitCode int

const (
	WRONG_INPUT_ARGS ExitCode = 1
	WRONG_PROTOCOL   ExitCode = 2
)
