// Copyright 2026 Michael VERGOZ
// SPDX-License-Identifier: MIT

package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Level int32

const (
	LevelError Level = 1 + iota
	LevelWarning
	LevelInfo
	LevelDebug
	LevelSuperDebug
)

const (
	cReset   = "\033[0m"
	cRed     = "\033[31m"
	cYellow  = "\033[33m"
	cCyan    = "\033[36m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cGray    = "\033[90m"
)

var currentLevel atomic.Int32

func Init(verboseCount int) {
	level := LevelInfo
	if verboseCount >= 2 {
		level = LevelSuperDebug
	} else if verboseCount == 1 {
		level = LevelDebug
	}
	currentLevel.Store(int32(level))

	log.SetFlags(0)
	log.SetOutput(&writer{out: os.Stderr})
}

func CurrentLevel() Level {
	return Level(currentLevel.Load())
}

func IsSuperDebug() bool {
	return CurrentLevel() >= LevelSuperDebug
}

func SuperDebugf(format string, args ...any) {
	log.Printf("[super-debug] "+format, args...)
}

type writer struct {
	out io.Writer
}

func (w *writer) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(p))
	if line == "" {
		return len(p), nil
	}

	level, label, color, msg := parse(line)
	if level > CurrentLevel() {
		return len(p), nil
	}

	ts := time.Now().Format("15:04:05")
	formatted := fmt.Sprintf(" %s%s%s %s%-5s%s %s",
		cGray, ts, cReset,
		color, label, cReset,
		msg)
	_, err := fmt.Fprintln(w.out, formatted)
	return len(p), err
}

func parse(line string) (Level, string, string, string) {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "[super-debug]"):
		return LevelSuperDebug, "TRACE", cMagenta, stripTag(line, "super-debug")
	case strings.Contains(lower, "[debug]"):
		return LevelDebug, "DEBUG", cBlue, stripTag(line, "debug")
	case strings.Contains(lower, "[info]"):
		return LevelInfo, "INFO", cCyan, stripTag(line, "info")
	case strings.Contains(lower, "[warn]"), strings.Contains(lower, "[warning]"):
		return LevelWarning, "WARN", cYellow, stripTag(line, "warn")
	case strings.Contains(lower, "[error]"):
		return LevelError, "ERROR", cRed, stripTag(line, "error")
	default:
		return LevelInfo, "INFO", cCyan, line
	}
}

func stripTag(line, level string) string {
	tag := "[" + level + "]"
	out := line
	idx := strings.Index(strings.ToLower(out), tag)
	if idx >= 0 {
		out = out[:idx] + out[idx+len(tag):]
	}
	return strings.TrimSpace(out)
}
