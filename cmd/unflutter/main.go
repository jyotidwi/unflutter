package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	cmd := os.Args[1]

	switch cmd {
	// --- Primary commands (new CLI) ---
	case "meta":
		err = cmdMeta(os.Args[2:])
	case "ghidra":
		err = cmdGhidra(os.Args[2:])
	case "ida":
		err = cmdIDA(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "find-libapp":
		err = cmdFindLibapp(os.Args[2:])
	case "parity":
		err = cmdParity(os.Args[2:])
	case "inventory":
		err = cmdInventory(os.Args[2:])
	case "_debug":
		err = cmdDebug(os.Args[2:])

	// --- Deprecated commands (shims with warnings) ---
	case "disasm":
		deprecationWarning("disasm", "unflutter <libapp.so>")
		err = cmdDisasm(os.Args[2:])
	case "signal":
		// "signal" with --in is the old form; without flags it's the new positional form.
		if hasFlag(os.Args[2:], "-in", "--in") {
			deprecationWarning("signal --in", "unflutter signal <libapp.so>")
			err = cmdSignal(os.Args[2:])
		} else {
			err = cmdSignalPipeline(os.Args[2:])
		}
	case "decompile":
		deprecationWarning("decompile", "unflutter ghidra <libapp.so>")
		err = cmdDecompile(os.Args[2:])
	case "flutter-meta", "ghidra-meta":
		deprecationWarning(cmd, "unflutter meta <libapp.so>")
		err = cmdFlutterMeta(os.Args[2:])
	case "scan":
		deprecationWarning("scan", "unflutter doctor <libapp.so> or unflutter _debug scan")
		err = cmdScan(os.Args[2:])
	case "dump":
		deprecationWarning("dump", "unflutter _debug dump")
		err = cmdDump(os.Args[2:])
	case "objects":
		deprecationWarning("objects", "unflutter _debug objects")
		err = cmdObjects(os.Args[2:])
	case "strings":
		deprecationWarning("strings", "unflutter _debug strings")
		err = cmdStrings(os.Args[2:])
	case "graph":
		deprecationWarning("graph", "unflutter _debug graph")
		err = cmdGraph(os.Args[2:])
	case "clusters":
		deprecationWarning("clusters", "unflutter _debug clusters")
		err = cmdClusters(os.Args[2:])
	case "render":
		deprecationWarning("render", "unflutter _debug render")
		err = cmdRender(os.Args[2:])
	case "thr-audit":
		deprecationWarning("thr-audit", "unflutter _debug thr-audit")
		err = cmdTHRAudit(os.Args[2:])
	case "thr-cluster":
		deprecationWarning("thr-cluster", "unflutter _debug thr-cluster")
		err = cmdTHRCluster(os.Args[2:])
	case "thr-classify":
		deprecationWarning("thr-classify", "unflutter _debug thr-classify")
		err = cmdTHRClassify(os.Args[2:])
	case "find-libapp-batch":
		deprecationWarning("find-libapp-batch", "unflutter _debug find-libapp-batch")
		err = cmdFindLibappBatch(os.Args[2:])
	case "dart2-buckets":
		deprecationWarning("dart2-buckets", "unflutter _debug dart2-buckets")
		err = cmdDart2Buckets(os.Args[2:])

	case "help", "-h", "--help":
		usage()
		os.Exit(0)

	default:
		// If the first arg is a file on disk, treat as "unflutter <libapp.so>".
		if resolvePositionalLib(cmd) != "" {
			err = cmdRun(os.Args[1:])
		} else if strings.HasPrefix(cmd, "-") {
			// Flags before file path: pass all args to cmdRun which will reorder.
			err = cmdRun(os.Args[1:])
		} else {
			fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
			usage()
			os.Exit(1)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func deprecationWarning(old, new string) {
	fmt.Fprintf(os.Stderr, "warning: '%s' is deprecated, use '%s' instead\n\n", old, new)
}

// hasFlag checks if any arg matches one of the given flag names.
func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

func usage() {
	fmt.Fprintf(os.Stderr, `unflutter — Dart AOT snapshot analyzer

Usage:
  unflutter <libapp.so>                         Full analysis pipeline
  unflutter meta <libapp.so>                    Generate flutter_meta.json
  unflutter ghidra <libapp.so>                   Ghidra headless decompilation
  unflutter ida <libapp.so>                     IDA headless decompilation
  unflutter signal <libapp.so>                  Signal analysis
  unflutter doctor <libapp.so>                  Diagnostic scan
  unflutter find-libapp <apk>                   Find Dart library in APK
  unflutter parity <dir>                        Corpus parity report
  unflutter inventory <dir>                     Sample inventory
  unflutter _debug <cmd>                        Internal commands

Flags:
  --out <dir>         Output directory (default: <basename>.unflutter/)
  --quiet, -q         Suppress verbose output (verbose is default)
  --strict            Fail on structural errors
  --all               Include all functions (not just signal)
  --from <dir>        Reuse existing disasm output
  --k <n>             Signal context hops (default: 2)
  --graph             Build call graph and per-function CFGs
  --max-steps <n>     Global loop cap
`)
}
