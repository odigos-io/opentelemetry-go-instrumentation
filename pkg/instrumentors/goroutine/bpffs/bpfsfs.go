package bpffs

import "path"

const (
	BpfFsPath     = "/sys/fs/bpf"
	GoRoutinesDir = "goroutines"
	AllocDir      = "alloc"
)

var (
	GoRoutinesMapDir = path.Join(BpfFsPath, GoRoutinesDir)
	AllocMapDir      = path.Join(BpfFsPath, AllocDir)
)
