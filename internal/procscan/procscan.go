// Package procscan seeds the store with processes that were already
// running when `provctl watch` started.
//
// Without this, the first thing a fresh daemon sees is a file being opened
// by a pid it has never heard of — so `provctl trace` can say a path was
// opened but not by whom, which is precisely the question it exists to
// answer. Most real activity right after startup involves long-lived
// processes (shells, browsers, desktop apps) that forked long before the
// daemon did.
//
// These are a best-effort snapshot, not observed events: /proc can only
// tell us a process's *current* identity, so a process that exec'd several
// times before we looked shows only its latest image.
package procscan

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thefoulowl/provctl/internal/model"
)

// userHZ is the fixed scale of the starttime field in /proc/<pid>/stat.
// The kernel always reports these in USER_HZ (100), independent of the
// kernel's internal CONFIG_HZ.
const userHZ = 100

// Snapshot enumerates /proc and returns one synthetic EXEC event per live
// process, timestamped with that process's real start time so ordering
// against subsequently observed events stays correct. selfPID is skipped
// (provctl doesn't trace itself).
//
// Individual unreadable processes are skipped rather than failing the
// whole scan: pids come and go while we walk, and kernel threads deny
// access to some of these files.
func Snapshot(selfPID uint32) ([]model.Event, error) {
	bootTime, err := bootTime()
	if err != nil {
		return nil, fmt.Errorf("procscan: %w", err)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("procscan: read /proc: %w", err)
	}

	var out []model.Event
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Parsed directly as uint32 (not int, then narrowed) to match
		// model.Event.PID's type with no intermediate architecture-
		// dependent conversion for static analysis to flag.
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a pid directory
		}
		pid := uint32(pid64)
		if pid == selfPID {
			continue // it's us
		}
		ev, ok := scanPID(pid, bootTime)
		if !ok {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

func scanPID(pid uint32, boot time.Time) (model.Event, bool) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return model.Event{}, false // exited between ReadDir and now
	}
	comm, ppid, startTicks, err := parseStat(string(raw))
	if err != nil {
		return model.Event{}, false
	}
	uptime, ok := ticksToDuration(startTicks)
	if !ok {
		return model.Event{}, false
	}

	ev := model.Event{
		Type: model.TypeExec,
		Time: boot.Add(uptime),
		PID:  pid,
		PPID: ppid,
		Comm: comm,
	}

	// The executable path is unavailable for kernel threads and for
	// processes we can't read; comm alone is still worth recording.
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		ev.Filename = exe
	}

	if fi, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			ev.UID, ev.GID = st.Uid, st.Gid
		}
	}

	return ev, true
}

// ticksToDuration converts a /proc/<pid>/stat starttime (USER_HZ clock
// ticks since boot) to a time.Duration. time.Duration is int64, and
// startTicks is a raw uint64 parse of a kernel field this package doesn't
// otherwise range-check, so the conversion is bounds-checked explicitly
// rather than letting an implausible value wrap to a negative duration
// silently. A value this large — system uptime beyond ~2.9 billion years
// at USER_HZ — can't occur in practice; ok is false only in that case.
func ticksToDuration(startTicks uint64) (d time.Duration, ok bool) {
	if startTicks > math.MaxInt64 {
		return 0, false
	}
	return time.Duration(startTicks) * time.Second / userHZ, true
}

// parseStat extracts comm, ppid, and starttime from a /proc/<pid>/stat
// line. The comm field is wrapped in parentheses and may itself contain
// spaces and parentheses (a process can set an arbitrary name), so the
// fields after it are located from the *last* ')' rather than by splitting
// the whole line on spaces.
func parseStat(line string) (comm string, ppid uint32, startTicks uint64, err error) {
	openIdx := strings.IndexByte(line, '(')
	closeIdx := strings.LastIndexByte(line, ')')
	if openIdx < 0 || closeIdx < 0 || closeIdx < openIdx {
		return "", 0, 0, fmt.Errorf("procscan: malformed stat line")
	}
	comm = line[openIdx+1 : closeIdx]

	// Fields after comm, 1-indexed as in proc(5): [0]=state(3), [1]=ppid(4),
	// ... starttime is field 22, i.e. index 19 here.
	rest := strings.Fields(line[closeIdx+1:])
	const (
		ppidIdx      = 1
		starttimeIdx = 19
	)
	if len(rest) <= starttimeIdx {
		return "", 0, 0, fmt.Errorf("procscan: stat line has %d fields after comm, want > %d", len(rest), starttimeIdx)
	}
	var parsedPPID uint64
	if parsedPPID, err = strconv.ParseUint(rest[ppidIdx], 10, 32); err != nil {
		return "", 0, 0, fmt.Errorf("procscan: parse ppid: %w", err)
	}
	ppid = uint32(parsedPPID)
	if startTicks, err = strconv.ParseUint(rest[starttimeIdx], 10, 64); err != nil {
		return "", 0, 0, fmt.Errorf("procscan: parse starttime: %w", err)
	}
	return comm, ppid, startTicks, nil
}

// bootTime reads the wall-clock instant the system booted, which
// /proc/<pid>/stat's starttime is relative to.
func bootTime() (time.Time, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("read /proc/stat: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		field, value, ok := strings.Cut(line, " ")
		if !ok || field != "btime" {
			continue
		}
		secs, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse btime: %w", err)
		}
		return time.Unix(secs, 0), nil
	}
	return time.Time{}, fmt.Errorf("no btime field in /proc/stat")
}
