//go:build darwin && cgo

// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package metal

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unsafe"

	_ "embed"
)

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Metal -framework Foundation

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#import <stdio.h>
#import <string.h>
#import <stddef.h>
#import <stdint.h>

int metal_nsec3_benchmark_run(
    const char *msl_source, size_t msl_len,
    const void *wire_blob, size_t wire_blob_len,
    const uint32_t *offsets, const uint32_t *lengths, uint32_t count,
    const void *salt, uint32_t salt_len, uint32_t nsec3_iterations,
    void *digests_out, char *errbuf, size_t errbuf_len)
{
    @autoreleasepool {
        if (count == 0) {
            snprintf(errbuf, errbuf_len, "count is zero");
            return -1;
        }
        id<MTLDevice> device = MTLCreateSystemDefaultDevice();
        if (!device) {
            snprintf(errbuf, errbuf_len, "no Metal device");
            return -2;
        }
        NSString *src = [[NSString alloc] initWithBytes:msl_source
                                                 length:msl_len
                                               encoding:NSUTF8StringEncoding];
        if (!src) {
            snprintf(errbuf, errbuf_len, "invalid MSL UTF-8");
            return -3;
        }
        NSError *err = nil;
        MTLCompileOptions *opts = [[MTLCompileOptions alloc] init];
        id<MTLLibrary> lib = [device newLibraryWithSource:src options:opts error:&err];
        if (!lib) {
            snprintf(errbuf, errbuf_len, "MSL compile: %s",
                     err ? [[err localizedDescription] UTF8String] : "unknown");
            return -4;
        }
        id<MTLFunction> fn = [lib newFunctionWithName:@"nsec3_benchmark_kernel"];
        if (!fn) {
            snprintf(errbuf, errbuf_len, "kernel nsec3_benchmark_kernel not found");
            return -5;
        }
        id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:fn error:&err];
        if (!pipeline) {
            snprintf(errbuf, errbuf_len, "pipeline: %s",
                     err ? [[err localizedDescription] UTF8String] : "unknown");
            return -6;
        }
        id<MTLCommandQueue> queue = [device newCommandQueue];
        id<MTLBuffer> bufWire = [device newBufferWithBytes:wire_blob
                                                    length:wire_blob_len
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufOff = [device newBufferWithBytes:offsets
                                                   length:count * sizeof(uint32_t)
                                                  options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufLen = [device newBufferWithBytes:lengths
                                                   length:count * sizeof(uint32_t)
                                                  options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufSalt;
        if (salt_len > 0) {
            bufSalt = [device newBufferWithBytes:salt
                                           length:salt_len
                                          options:MTLResourceStorageModeShared];
        } else {
            // Keep a bound buffer even when salt is empty.
            uint8_t zero = 0;
            bufSalt = [device newBufferWithBytes:&zero
                                           length:1
                                          options:MTLResourceStorageModeShared];
        }
        uint32_t sl = salt_len;
        id<MTLBuffer> bufSaltLen = [device newBufferWithBytes:&sl
                                                       length:sizeof(uint32_t)
                                                      options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufIter = [device newBufferWithBytes:&nsec3_iterations
                                                    length:sizeof(uint32_t)
                                                   options:MTLResourceStorageModeShared];
        id<MTLBuffer> bufOut = [device newBufferWithLength:count * 20
                                                     options:MTLResourceStorageModeShared];
        id<MTLCommandBuffer> cmd = [queue commandBuffer];
        id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
        [enc setComputePipelineState:pipeline];
        [enc setBuffer:bufWire offset:0 atIndex:0];
        [enc setBuffer:bufOff offset:0 atIndex:1];
        [enc setBuffer:bufLen offset:0 atIndex:2];
        [enc setBuffer:bufSalt offset:0 atIndex:3];
        [enc setBuffer:bufSaltLen offset:0 atIndex:4];
        [enc setBuffer:bufIter offset:0 atIndex:5];
        [enc setBuffer:bufOut offset:0 atIndex:6];
        NSUInteger maxTG = pipeline.maxTotalThreadsPerThreadgroup;
        if (maxTG < 64) maxTG = 64;
        if (maxTG > 256) maxTG = 256;
        MTLSize grid = MTLSizeMake(count, 1, 1);
        MTLSize tg = MTLSizeMake(maxTG, 1, 1);
        [enc dispatchThreads:grid threadsPerThreadgroup:tg];
        [enc endEncoding];
        [cmd commit];
        [cmd waitUntilCompleted];
        if (cmd.error) {
            snprintf(errbuf, errbuf_len, "GPU: %s", [[cmd.error localizedDescription] UTF8String]);
            return -7;
        }
        memcpy(digests_out, [bufOut contents], count * 20);
        return 0;
    }
}

void metal_device_name_copy(char *dst, size_t dstlen) {
    if (!dst || dstlen == 0) return;
    dst[0] = 0;
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) return;
    const char *s = [device.name UTF8String];
    if (s) strncpy(dst, s, dstlen - 1);
}
*/
import "C"

//go:embed kernel.metal
var kernelMSL string

var base32HexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)

func packName(name string) []byte {
	var buf []byte
	name = strings.TrimSuffix(name, ".")
	for _, l := range strings.Split(name, ".") {
		buf = append(buf, byte(len(l)))
		buf = append(buf, []byte(l)...)
	}
	buf = append(buf, 0)
	return buf
}

func cpuNSEC3Digest(label, zone string, iterations uint16, saltHex string) ([]byte, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, err
	}
	fqdn := strings.ToLower(label + "." + zone)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	wire := packName(fqdn)
	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	digest := h.Sum(nil)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}
	return digest, nil
}

// HashBatch computes NSEC3 hashes for labels under zone on the Metal GPU and returns label->Base32Hex hash.
func HashBatch(labels []string, zone string, nsec3Iter uint16, saltHex string) (map[string]string, string, error) {
	if len(labels) == 0 {
		return map[string]string{}, "GPU (Metal)", nil
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return nil, "", fmt.Errorf("salt hex: %w", err)
	}

	var blob []byte
	offsets := make([]uint32, len(labels))
	lengths := make([]uint32, len(labels))
	for i, label := range labels {
		offsets[i] = uint32(len(blob))
		fqdn := strings.ToLower(label + "." + zone)
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		w := packName(fqdn)
		lengths[i] = uint32(len(w))
		blob = append(blob, w...)
	}

	digests := make([]byte, len(labels)*20)
	errBuf := make([]byte, 1024)
	mslBytes := []byte(kernelMSL)

	var saltPtr unsafe.Pointer
	if len(salt) > 0 {
		saltPtr = unsafe.Pointer(&salt[0])
	}
	rc := C.metal_nsec3_benchmark_run(
		(*C.char)(unsafe.Pointer(&mslBytes[0])),
		C.size_t(len(mslBytes)),
		unsafe.Pointer(&blob[0]),
		C.size_t(len(blob)),
		(*C.uint32_t)(unsafe.Pointer(&offsets[0])),
		(*C.uint32_t)(unsafe.Pointer(&lengths[0])),
		C.uint32_t(len(labels)),
		saltPtr,
		C.uint32_t(len(salt)),
		C.uint32_t(nsec3Iter),
		unsafe.Pointer(&digests[0]),
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	if rc != 0 {
		msg := C.GoString((*C.char)(unsafe.Pointer(&errBuf[0])))
		return nil, "", fmt.Errorf("Metal: %s", msg)
	}

	// Cross-check a few labels against CPU to catch kernel/drivers regressions.
	check := len(labels)
	if check > 8 {
		check = 8
	}
	for i := 0; i < check; i++ {
		want, err := cpuNSEC3Digest(labels[i], zone, nsec3Iter, saltHex)
		if err != nil {
			return nil, "", err
		}
		got := digests[i*20 : i*20+20]
		if !bytes.Equal(want, got) {
			return nil, "", fmt.Errorf("GPU/CPU mismatch at label %q", labels[i])
		}
	}

	out := make(map[string]string, len(labels))
	for i, label := range labels {
		d := digests[i*20 : i*20+20]
		out[label] = strings.ToUpper(base32HexNoPad.EncodeToString(d))
	}

	var nameBuf [512]byte
	C.metal_device_name_copy((*C.char)(unsafe.Pointer(&nameBuf[0])), C.size_t(len(nameBuf)))
	deviceName := C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))
	if deviceName == "" {
		deviceName = "GPU (Metal)"
	} else {
		deviceName = "GPU (Metal) — " + deviceName
	}

	return out, deviceName, nil
}

// RunMetalBenchmark runs the NSEC3 SHA-1 workload on the default Metal GPU.
// iterations is the number of labels test0..test{n-1} (same workload shape as the CPU benchmark).
func RunMetalBenchmark(iterations int, zone string, nsec3Iter uint16, saltHex string) (hashesPerSec float64, deviceName string, elapsed time.Duration, total uint64, err error) {
	if iterations <= 0 {
		return 0, "", 0, 0, fmt.Errorf("iterations must be positive")
	}
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return 0, "", 0, 0, fmt.Errorf("salt hex: %w", err)
	}

	var blob []byte
	offsets := make([]uint32, iterations)
	lengths := make([]uint32, iterations)
	for i := 0; i < iterations; i++ {
		offsets[i] = uint32(len(blob))
		label := fmt.Sprintf("test%d", i)
		fqdn := strings.ToLower(label + "." + zone)
		if !strings.HasSuffix(fqdn, ".") {
			fqdn += "."
		}
		w := packName(fqdn)
		lengths[i] = uint32(len(w))
		blob = append(blob, w...)
	}

	digests := make([]byte, iterations*20)
	errBuf := make([]byte, 1024)
	mslBytes := []byte(kernelMSL)

	start := time.Now()
	var saltPtr unsafe.Pointer
	if len(salt) > 0 {
		saltPtr = unsafe.Pointer(&salt[0])
	}
	rc := C.metal_nsec3_benchmark_run(
		(*C.char)(unsafe.Pointer(&mslBytes[0])),
		C.size_t(len(mslBytes)),
		unsafe.Pointer(&blob[0]),
		C.size_t(len(blob)),
		(*C.uint32_t)(unsafe.Pointer(&offsets[0])),
		(*C.uint32_t)(unsafe.Pointer(&lengths[0])),
		C.uint32_t(iterations),
		saltPtr,
		C.uint32_t(len(salt)),
		C.uint32_t(nsec3Iter),
		unsafe.Pointer(&digests[0]),
		(*C.char)(unsafe.Pointer(&errBuf[0])),
		C.size_t(len(errBuf)),
	)
	elapsed = time.Since(start)
	if rc != 0 {
		msg := C.GoString((*C.char)(unsafe.Pointer(&errBuf[0])))
		return 0, "", 0, 0, fmt.Errorf("Metal: %s", msg)
	}

	for i := 0; i < iterations && i < 50; i++ {
		want, err := cpuNSEC3Digest(fmt.Sprintf("test%d", i), zone, nsec3Iter, saltHex)
		if err != nil {
			return 0, "", 0, 0, err
		}
		got := digests[i*20 : i*20+20]
		if !bytes.Equal(want, got) {
			return 0, "", 0, 0, fmt.Errorf("GPU/CPU mismatch at test%d", i)
		}
	}

	var nameBuf [512]byte
	C.metal_device_name_copy((*C.char)(unsafe.Pointer(&nameBuf[0])), C.size_t(len(nameBuf)))
	deviceName = C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0])))

	total = uint64(iterations)
	if elapsed.Seconds() > 0 {
		hashesPerSec = float64(iterations) / elapsed.Seconds()
	}
	if deviceName == "" {
		deviceName = "Metal GPU"
	} else {
		deviceName = "GPU (Metal) — " + deviceName
	}
	return hashesPerSec, deviceName, elapsed, total, nil
}

// DefaultDeviceName returns the default Metal GPU device name (e.g. "Apple M1 Ultra"), or "" if none.
func DefaultDeviceName() string {
	var nameBuf [512]byte
	C.metal_device_name_copy((*C.char)(unsafe.Pointer(&nameBuf[0])), C.size_t(len(nameBuf)))
	return strings.TrimSpace(C.GoString((*C.char)(unsafe.Pointer(&nameBuf[0]))))
}
