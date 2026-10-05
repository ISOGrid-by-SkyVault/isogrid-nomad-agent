// Package builds turns a repository at a commit into an image, on the
// customer's own engine. The source is downloaded from the customer's code
// host with the customer's token, built by the local Docker engine and pushed
// to the customer's registry. ISOGrid asks for a build and later asks how it
// ended; it receives the commit id, the image name and its digest. The code
// and the build output never leave this machine.
//
// A build runs detached from the stream: a dropped connection does not kill
// it, and ISOGrid finds its outcome with `build.status` when it reconnects.
package builds

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/connections"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/docker"
	"github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent/internal/store"
)

// Request is `build.run`.
type Request struct {
	Connection     string `json:"connection"`      // GitHub or GitLab connection
	Repository     string `json:"repository"`      // owner/name or group/project
	Ref            string `json:"ref"`             // branch, tag or commit
	Dockerfile     string `json:"dockerfile"`      // path inside the context
	Context        string `json:"context"`         // sub-directory to build from
	Image          string `json:"image"`           // full reference to tag and push
	PushConnection string `json:"push_connection"` // registry connection; empty keeps the image local
}

const (
	maxConcurrent = 2
	buildTimeout  = 30 * time.Minute
	maxLogBytes   = 20 << 20
	keepLogs      = 100
)

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{7,63}$`)
	imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,254}$`)
)

// Runner runs builds.
type Runner struct {
	Sources *connections.Manager
	Docker  *docker.Client
	Store   *store.Store
	Dir     string // where build logs are kept
	Logf    func(format string, args ...any)

	once  sync.Once
	slots chan struct{}
}

func (r *Runner) init() {
	r.once.Do(func() { r.slots = make(chan struct{}, maxConcurrent) })
}

// LogPath is where a build's output is kept.
func (r *Runner) LogPath(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", errors.New("not a build id")
	}
	return filepath.Join(r.Dir, id+".log"), nil
}

func cleanRelative(p, what string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." {
		return "", nil
	}
	clean := path.Clean(strings.ReplaceAll(p, "\\", "/"))
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || len(clean) > 255 {
		return "", fmt.Errorf("the %s must be a path inside the repository", what)
	}
	return clean, nil
}

// Start validates a request, records the build and runs it in the
// background. Starting an id that already exists returns that build: an
// intent delivered twice builds once.
func (r *Runner) Start(ctx context.Context, id string, req Request) (*store.Build, error) {
	r.init()
	if !idPattern.MatchString(id) {
		return nil, errors.New("not a build id")
	}
	var err error
	if req.Repository, err = connections.CleanRepository(req.Repository); err != nil {
		return nil, err
	}
	if req.Ref, err = connections.CleanRef(req.Ref); err != nil {
		return nil, err
	}
	if req.Dockerfile, err = cleanRelative(req.Dockerfile, "Dockerfile path"); err != nil {
		return nil, err
	}
	if req.Context, err = cleanRelative(req.Context, "build context"); err != nil {
		return nil, err
	}
	if !imagePattern.MatchString(req.Image) || strings.Contains(req.Image, "..") || strings.Contains(req.Image, "//") {
		return nil, fmt.Errorf("image reference %q is not valid", req.Image)
	}
	if req.PushConnection != "" {
		// Fails now, with a clear reason, rather than after ten minutes of build.
		if _, err := r.Sources.RegistryAuth(ctx, req.PushConnection, req.Image); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(r.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("build log directory: %w", err)
	}
	build := store.Build{
		ID: id, Connection: req.Connection, Repository: req.Repository, Ref: req.Ref,
		Image: req.Image, Status: "running", StartedAt: time.Now(),
	}
	created, err := r.Store.CreateBuild(ctx, build)
	if err != nil {
		return nil, err
	}
	if !created {
		return r.Store.GetBuild(ctx, id)
	}
	go r.run(build, req)
	return &build, nil
}

// Status returns a build as recorded.
func (r *Runner) Status(ctx context.Context, id string) (*store.Build, error) {
	if !idPattern.MatchString(id) {
		return nil, errors.New("not a build id")
	}
	return r.Store.GetBuild(ctx, id)
}

// capped stops writing after a limit, so a runaway build cannot fill the disk.
type capped struct {
	w    io.Writer
	left int64
}

func (c *capped) Write(p []byte) (int, error) {
	if c.left <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > c.left {
		_, _ = c.w.Write(p[:c.left])
		_, _ = io.WriteString(c.w, "\n[output truncated]\n")
		c.left = 0
		return len(p), nil
	}
	c.left -= int64(len(p))
	return c.w.Write(p)
}

func (r *Runner) run(build store.Build, req Request) {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	logPath, _ := r.LogPath(build.ID)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	var out io.Writer = io.Discard
	if err == nil {
		defer file.Close()
		out = &capped{w: file, left: maxLogBytes}
	}
	say := func(format string, args ...any) {
		fmt.Fprintf(out, "[%s] %s\n", time.Now().UTC().Format("15:04:05"), fmt.Sprintf(format, args...))
	}

	finish := func(failure error) {
		build.FinishedAt = time.Now()
		if failure != nil {
			build.Status = "failed"
			build.Error = failure.Error()
			if len(build.Error) > 600 {
				build.Error = build.Error[:600]
			}
			say("Failed: %s", build.Error)
		} else {
			build.Status = "succeeded"
			say("Done in %s", build.FinishedAt.Sub(build.StartedAt).Round(time.Second))
		}
		saveCtx, saveCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer saveCancel()
		if err := r.Store.UpdateBuild(saveCtx, build); err != nil {
			r.Logf("builds: %s finished but could not be recorded: %v", build.ID, err)
		}
		r.Logf("builds: %s %s (%s@%s -> %s)", build.ID, build.Status, build.Repository, build.Ref, build.Image)
		r.pruneLogs(saveCtx)
	}

	select {
	case r.slots <- struct{}{}:
	default:
		say("Waiting for a free build slot (%d run at a time)", maxConcurrent)
		select {
		case r.slots <- struct{}{}:
		case <-ctx.Done():
			finish(errors.New("timed out waiting for a free build slot"))
			return
		}
	}
	defer func() { <-r.slots }()

	say("Fetching %s at %s through connection %s", req.Repository, req.Ref, req.Connection)
	source, err := r.Sources.Archive(ctx, req.Connection, req.Repository, req.Ref)
	if err != nil {
		finish(err)
		return
	}
	defer source.Archive.Close()
	build.Commit = source.Commit
	_ = r.Store.UpdateBuild(ctx, build)
	say("Commit %s", source.Commit)

	reader, writer := io.Pipe()
	go func() { writer.CloseWithError(Repack(source.Archive, writer, req.Context)) }()

	say("Building %s", req.Image)
	err = r.Docker.Build(ctx, reader, docker.BuildOptions{
		Tag: req.Image, Dockerfile: req.Dockerfile, Pull: true,
		Labels: map[string]string{
			"isogrid.build":      build.ID,
			"isogrid.repository": req.Repository,
			"isogrid.commit":     source.Commit,
		},
	}, out)
	_ = reader.CloseWithError(errors.New("build ended"))
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("the build passed its limit of %s", buildTimeout)
		}
		finish(err)
		return
	}

	if req.PushConnection != "" {
		auth, err := r.Sources.RegistryAuth(ctx, req.PushConnection, req.Image)
		if err != nil {
			finish(err)
			return
		}
		say("Pushing %s through connection %s", req.Image, req.PushConnection)
		digest, err := r.Docker.Push(ctx, req.Image, auth, out)
		if err != nil {
			finish(fmt.Errorf("the image was built but the push failed: %w", err))
			return
		}
		build.Digest = digest
	} else {
		say("No registry connection named: the image stays on this node")
	}
	finish(nil)
}

// pruneLogs removes the output of builds past the newest keepLogs.
func (r *Runner) pruneLogs(ctx context.Context) {
	recent, err := r.Store.ListBuilds(ctx, keepLogs)
	if err != nil {
		return
	}
	keep := make(map[string]bool, len(recent))
	for _, b := range recent {
		keep[b.ID+".log"] = true
	}
	entries, err := os.ReadDir(r.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") && !keep[e.Name()] {
			_ = os.Remove(filepath.Join(r.Dir, e.Name()))
		}
	}
}

// Repack turns the archive a code host serves into a Docker build context:
// the single top-level directory those archives wrap everything in is
// removed and, when `subdir` is given, only that directory is kept, as the
// root. Entries that would leave the context are dropped.
func Repack(archive io.Reader, out io.Writer, subdir string) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return fmt.Errorf("the source archive is not gzip: %w", err)
	}
	defer gz.Close()
	in := tar.NewReader(gz)
	tw := tar.NewWriter(out)
	kept := 0
	for {
		header, err := in.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("the source archive is damaged: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		_, rest, found := strings.Cut(strings.TrimPrefix(header.Name, "./"), "/")
		if !found || rest == "" {
			continue // the wrapping directory itself
		}
		name := path.Clean(rest)
		if subdir != "" {
			if name != subdir && !strings.HasPrefix(name, subdir+"/") {
				continue
			}
			name = strings.TrimPrefix(strings.TrimPrefix(name, subdir), "/")
			if name == "" {
				continue
			}
		}
		if name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeDir, tar.TypeSymlink:
		default:
			continue // devices, hard links and the like have no place in source
		}
		next := *header
		next.Name = name
		if header.Typeflag == tar.TypeDir {
			next.Name += "/"
		}
		if err := tw.WriteHeader(&next); err != nil {
			return err
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := io.Copy(tw, in); err != nil {
				return err
			}
		}
		kept++
	}
	if kept == 0 {
		if subdir != "" {
			return fmt.Errorf("the repository has no directory %q at that commit", subdir)
		}
		return errors.New("the repository is empty at that commit")
	}
	return tw.Close()
}
