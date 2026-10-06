package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Against a real engine: a build from a tar context, as the build runner
// sends it. Run with NOMAD_LIVE_DOCKER=1 and the socket available.
func TestLiveBuild(t *testing.T) {
	if os.Getenv("NOMAD_LIVE_DOCKER") == "" {
		t.Skip("set NOMAD_LIVE_DOCKER=1 with a Docker socket to build for real")
	}
	client, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string]string{
		"docker/Dockerfile": "FROM alpine:3.20\nCOPY hello.txt /hello.txt\nRUN test -s /hello.txt && echo built-by-selftest\n",
		"hello.txt":         "hi\n",
	}
	for name, body := range files {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()

	const tag = "isogrid-nomad-selftest:live"
	var log bytes.Buffer
	err = client.Build(ctx, &buf, BuildOptions{Tag: tag, Dockerfile: "docker/Dockerfile", Pull: true, Labels: map[string]string{"isogrid.build": "selftest"}}, &log)
	if err != nil {
		t.Fatalf("build: %v\n%s", err, log.String())
	}
	if !strings.Contains(log.String(), "built-by-selftest") {
		t.Fatalf("the build output did not reach the log:\n%s", log.String())
	}
	defer func() { _ = client.do(ctx, http.MethodDelete, "/images/"+tag, nil, nil, nil) }()

	// A Dockerfile that fails reports the engine's reason, not a bare status.
	var bad bytes.Buffer
	tw = tar.NewWriter(&bad)
	body := "FROM alpine:3.20\nRUN exit 7\n"
	_ = tw.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte(body))
	_ = tw.Close()
	log.Reset()
	err = client.Build(ctx, &bad, BuildOptions{Tag: "isogrid-nomad-selftest:bad"}, &log)
	if err == nil || !strings.Contains(err.Error(), "7") {
		t.Fatalf("a failing build: %v\n%s", err, log.String())
	}
}

// Against a real engine: a one-off job fed on stdin, as the database
// provisioner's client containers are. Run with NOMAD_LIVE_DOCKER=1.
func TestLiveRunJob(t *testing.T) {
	if os.Getenv("NOMAD_LIVE_DOCKER") == "" {
		t.Skip("set NOMAD_LIVE_DOCKER=1 with a Docker socket to run a job for real")
	}
	client, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	result, err := client.RunJob(ctx, JobSpec{
		Image:   "alpine:3.20",
		Command: []string{"sh", "-c", "cat; echo from-stderr >&2; exit 3"},
		Env:     []string{"A=1"},
		Stdin:   "hello from stdin\nsecond line\n",
		Labels:  map[string]string{"isogrid.managed": "true"},
		Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 3 || !strings.Contains(result.Stdout, "second line") || !strings.Contains(result.Stderr, "from-stderr") {
		t.Fatalf("unexpected result: %+v", result)
	}
	// A job that overruns is killed and says so.
	quick, err := client.RunJob(ctx, JobSpec{Image: "alpine:3.20", Command: []string{"sleep", "30"}, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !quick.TimedOut || quick.ExitCode != 124 {
		t.Fatalf("expected a timeout: %+v", quick)
	}
}
