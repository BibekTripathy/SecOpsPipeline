package gitutil

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ImportObjects copies the objects in srcObjectDir into repo's own object
// store.
//
// This exists because of how git's receive-pack quarantine behaves: when
// the pre-receive hook exits non-zero, git throws the incoming objects
// away. That is exactly right for a rejected push, and exactly wrong for
// a held one -- a hold must reject at the git level, so the developer
// does not believe the push succeeded, while keeping the objects for a
// reviewer to approve later.
//
// Copying is safe because git objects are immutable and content
// addressed: a loose object or packfile means the same thing in any
// repository, which is why git's own quarantine migration is a move of
// these same files. Existing files are left alone rather than
// overwritten.
func ImportObjects(ctx context.Context, repo Repo, srcObjectDir string) error {
	if srcObjectDir == "" {
		return nil
	}
	dstObjectDir := filepath.Join(repo.Path, "objects")

	err := filepath.Walk(srcObjectDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(srcObjectDir, path)
		if err != nil {
			return err
		}
		// alternates and other metadata describe the source repository,
		// not its contents, and must not follow the objects across.
		if strings.HasPrefix(rel, "info"+string(filepath.Separator)) {
			return nil
		}

		dst := filepath.Join(dstObjectDir, rel)
		if _, err := os.Stat(dst); err == nil {
			return nil // already present; objects are immutable
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return copyFile(path, dst)
	})
	if err != nil {
		return fmt.Errorf("import objects from %s: %w", srcObjectDir, err)
	}
	return nil
}

// copyFile writes src to dst via a temporary file, so a crash midway
// cannot leave a truncated object that git would later read as corrupt.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".import-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o444); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// Anchor points a ref at a commit so its objects stay reachable and are
// not reclaimed by a later gc.
func Anchor(ctx context.Context, repo Repo, ref, rev string) error {
	if _, err := Run(ctx, repo, "update-ref", ref, rev); err != nil {
		return fmt.Errorf("anchor %s at %s: %w", ref, rev, err)
	}
	return nil
}
