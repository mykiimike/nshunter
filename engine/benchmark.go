// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package engine

import (
	"fmt"
	"runtime"
	"time"

	"github.com/mykiimike/nshunter/metal"
)

func Benchmark(useGPU bool) (*BenchmarkResult, error) {
	if useGPU {
		return benchmarkGPU()
	}
	return benchmarkCPU()
}

func benchmarkCPU() (*BenchmarkResult, error) {
	const iterations = 1_000_000
	salt := "aabbccdd"
	zone := "benchmark.test"

	nh, err := newNSEC3Hasher(zone, 10, salt)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	for i := 0; i < iterations; i++ {
		label := fmt.Sprintf("test%d", i)
		nh.Hash(label)
	}
	elapsed := time.Since(start)

	return &BenchmarkResult{
		Device:       fmt.Sprintf("CPU (%s/%s, %d cores)", runtime.GOOS, runtime.GOARCH, runtime.NumCPU()),
		HashesPerSec: float64(iterations) / elapsed.Seconds(),
		Duration:     elapsed,
		TotalHashes:  iterations,
	}, nil
}

func benchmarkGPU() (*BenchmarkResult, error) {
	const iterations = 1_000_000
	salt := "aabbccdd"
	zone := "benchmark.test"
	const nsec3Iter = uint16(10)

	hps, dev, elapsed, total, err := metal.RunMetalBenchmark(iterations, zone, nsec3Iter, salt)
	if err != nil {
		return nil, err
	}

	return &BenchmarkResult{
		Device:       dev,
		HashesPerSec: hps,
		Duration:     elapsed,
		TotalHashes:  total,
	}, nil
}
