package bench

import (
	"context"
	"fmt"
	"testing"
)

// pushSizes are the shapes a push actually takes: a one-file fix, a
// feature branch, a large refactor, a vendored-dependency drop.
var pushSizes = []struct {
	name      string
	files     int
	fileBytes int
	commits   int
}{
	{"1file_4KB", 1, 4 << 10, 1},
	{"10files_4KB", 10, 4 << 10, 1},
	{"50files_8KB", 50, 8 << 10, 5},
	{"200files_8KB", 200, 8 << 10, 10},
	{"500files_16KB", 500, 16 << 10, 20},
	{"50files_256KB", 50, 256 << 10, 5},
}

// BenchmarkScan measures the whole scan stage: describing the push, then
// running every plugin over it. This is the latency the gateway adds.
func BenchmarkScan(b *testing.B) {
	for _, size := range pushSizes {
		b.Run(size.name, func(b *testing.B) {
			f := buildFixture(b, size.files, size.fileBytes, size.commits)
			reg := newRegistry()
			ctx := context.Background()

			b.SetBytes(f.bytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				target := withBlobs(b, f, describe(b, f))
				results := reg.Run(ctx, target, 4)
				for _, r := range results {
					if r.Err != nil {
						b.Fatalf("scanner %s: %v", r.Scanner, r.Err)
					}
				}
			}
		})
	}
}

// BenchmarkDescribe isolates the git plumbing, so a regression can be
// attributed to the scanners or to the description, not just "the scan".
func BenchmarkDescribe(b *testing.B) {
	for _, size := range pushSizes {
		b.Run(size.name, func(b *testing.B) {
			f := buildFixture(b, size.files, size.fileBytes, size.commits)
			b.SetBytes(f.bytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				describe(b, f)
			}
		})
	}
}

// BenchmarkScanWorkers measures what parallelism buys. The answer informs
// the default for scan.workers, and with only two plugins registered it is
// expected to be modest -- the pool parallelises across plugins, not
// across files.
func BenchmarkScanWorkers(b *testing.B) {
	f := buildFixture(b, 200, 8<<10, 10)
	reg := newRegistry()
	ctx := context.Background()

	for _, workers := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("workers_%d", workers), func(b *testing.B) {
			target := withBlobs(b, f, describe(b, f))
			b.SetBytes(f.bytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				reg.Run(ctx, target, workers)
			}
		})
	}
}

// BenchmarkSecretsScanContent isolates the detection layers from all git
// and filesystem cost, which is the number to watch when a rule is added.
func BenchmarkSecretsScanContent(b *testing.B) {
	content := []byte(sourceLikeFixed(64 << 10))
	s := newSecretsScanner()
	ctx := context.Background()

	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ScanContent(ctx, "pkg/file.go", content)
	}
}
