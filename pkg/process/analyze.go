// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package process

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/hashicorp/go-version"

	"go.opentelemetry.io/auto/pkg/log"
	"go.opentelemetry.io/auto/pkg/process/ptrace"
)

// TargetDetails are the details about a target function.
type TargetDetails struct {
	PID               int
	Functions         []*Func
	GoVersion         *version.Version
	Libraries         map[string]string
	AllocationDetails *AllocationDetails
}

// AllocationDetails are the details about allocated memory.
type AllocationDetails struct {
	StartAddr uint64
	EndAddr   uint64
}

// Func represents a function target.
type Func struct {
	Name          string
	Offset        uint64
	ReturnOffsets []uint64
}

// IsRegistersABI returns if t is supported.
func (t *TargetDetails) IsRegistersABI() bool {
	regAbiMinVersion, _ := version.NewVersion("1.17")
	return t.GoVersion.GreaterThanOrEqual(regAbiMinVersion)
}

// GetFunctionOffset returns the offset for of the function with name.
func (t *TargetDetails) GetFunctionOffset(name string) (uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.Offset, nil
		}
	}

	return 0, fmt.Errorf("could not find offset for function %s", name)
}

// GetFunctionReturns returns the return value of the call for the function
// with name.
func (t *TargetDetails) GetFunctionReturns(name string) ([]uint64, error) {
	for _, f := range t.Functions {
		if f.Name == name {
			return f.ReturnOffsets, nil
		}
	}

	return nil, fmt.Errorf("could not find returns for function %s", name)
}

func (a *Analyzer) remoteMmap(pid int, mapSize uint64) (uint64, error) {
	program, err := ptrace.NewTracedProgram(pid, log.Logger)
	if err != nil {
		log.Logger.Error(err, "Failed to attach ptrace", "pid", pid)
		return 0, err
	}

	defer func() {
		log.Logger.V(0).Info("Detaching from process", "pid", pid)
		err := program.Detach()
		if err != nil {
			log.Logger.Error(err, "Failed to detach ptrace", "pid", pid)
		}
	}()
	fd := -1
	addr, err := program.Mmap(mapSize, uint64(fd))
	if err != nil {
		log.Logger.Error(err, "Failed to mmap", "pid", pid)
		return 0, err
	}

	err = program.Madvise(addr, mapSize)
	if err != nil {
		log.Logger.Error(err, "Failed to madvise", "pid", pid)
		return 0, err
	}

	return addr, nil
}

// AllocateMemory allocates memory in the target process.
func (a *Analyzer) AllocateMemory(target *TargetDetails) (*AllocationDetails, error) {
	mapSize := uint64(os.Getpagesize() * runtime.NumCPU() * 50)
	addr, err := a.remoteMmap(target.PID, mapSize)
	if err != nil {
		log.Logger.Error(err, "Failed to mmap")
		return nil, err
	}

	log.Logger.V(0).Info("mmaped remote memory", "start_addr", fmt.Sprintf("%X", addr),
		"end_addr", fmt.Sprintf("%X", addr+mapSize))
	return &AllocationDetails{
		StartAddr: addr,
		EndAddr:   addr + mapSize,
	}, nil
}

// Analyze returns the target details for an actively running process.
func (a *Analyzer) Analyze(pid int, relevantFuncs map[string]interface{}) (*TargetDetails, error) {
	result := &TargetDetails{
		PID: pid,
	}

	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()
	elfF, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}

	goVersion, modules, err := a.getModuleDetails(elfF)
	if err != nil {
		return nil, err
	}
	result.GoVersion = goVersion
	result.Libraries = modules

	funcs, err := findFunctions(elfF, relevantFuncs)
	if err != nil {
		log.Logger.Error(err, "Failed to find functions")
		return nil, err
	}

	result.Functions = funcs
	if len(result.Functions) == 0 {
		return nil, errors.New("could not find function offsets for instrumenter")
	}

	return result, nil
}

func findFunctions(elfF *elf.File, relevantFuncs map[string]interface{}) ([]*Func, error) {
	result, err := FindFunctionsUnStripped(elfF, relevantFuncs)
	if err != nil {
		if errors.Is(err, elf.ErrNoSymbols) {
			log.Logger.V(0).Info("No symbols found in binary, trying to find functions using .gosymtab")
			return FindFunctionsStripped(elfF, relevantFuncs)
		}
		return nil, err
	}

	return result, nil
}
