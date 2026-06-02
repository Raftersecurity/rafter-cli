//go:build unix

package main

import "syscall"

// raiseFileLimit lifts the process's RLIMIT_NOFILE soft limit toward the
// hard limit so the file watcher (one descriptor per watched directory
// on macOS's kqueue backend) and the scanner have room to work on a
// large scan scope. Returns the new soft limit on success.
//
// It is deliberately conservative: it never tries to exceed the hard
// limit, and it caps the target at a sane ceiling so kernels that report
// RLIM_INFINITY as the hard max don't get an absurd request that they'd
// reject outright.
func raiseFileLimit() (uint64, error) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, err
	}

	// 65536 descriptors is far more than a file watcher needs and stays
	// under the per-process ceilings macOS and Linux actually enforce.
	const ceiling = 65536
	target := lim.Max
	if target == 0 || target > ceiling {
		target = ceiling
	}
	if lim.Cur >= target {
		return lim.Cur, nil // already at or above what we'd ask for
	}

	newLim := syscall.Rlimit{Cur: target, Max: lim.Max}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &newLim); err != nil {
		// Some kernels (older macOS) reject Cur == Max; retry at a
		// conservative fixed value still well above the 256 default.
		newLim.Cur = 10240
		if lim.Max != 0 && newLim.Cur > lim.Max {
			newLim.Cur = lim.Max
		}
		if err2 := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &newLim); err2 != nil {
			return 0, err
		}
	}
	return newLim.Cur, nil
}
