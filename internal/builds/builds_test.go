package builds

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"sort"
	"strings"
	"testing"
)

func archive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header"})
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "acme-app-1a2b3c/", Mode: 0o755})
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "acme-app-1a2b3c/" + name, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func entries(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = string(body)
	}
}

func TestRepack(t *testing.T) {
	src := archive(t, map[string]string{"Dockerfile": "FROM scratch", "api/Dockerfile": "FROM alpine", "api/main.go": "package main", "../escape": "x"})

	var whole bytes.Buffer
	if err := Repack(bytes.NewReader(src), &whole, ""); err != nil {
		t.Fatal(err)
	}
	got := entries(t, whole.Bytes())
	if got["Dockerfile"] != "FROM scratch" || got["api/main.go"] != "package main" {
		t.Fatalf("the wrapping directory was not removed: %v", got)
	}
	for name := range got {
		if strings.HasPrefix(name, "..") || strings.HasPrefix(name, "acme-app") || strings.HasPrefix(name, "/") {
			t.Fatalf("an entry left the context: %q", name)
		}
	}

	var sub bytes.Buffer
	if err := Repack(bytes.NewReader(src), &sub, "api"); err != nil {
		t.Fatal(err)
	}
	got = entries(t, sub.Bytes())
	if len(got) != 2 || got["Dockerfile"] != "FROM alpine" || got["main.go"] != "package main" {
		t.Fatalf("sub-directory context: %v", got)
	}

	if err := Repack(bytes.NewReader(src), io.Discard, "nope"); err == nil || !strings.Contains(err.Error(), "no directory") {
		t.Fatalf("a missing sub-directory: %v", err)
	}
	if err := Repack(strings.NewReader("not gzip"), io.Discard, ""); err == nil {
		t.Fatal("garbage was accepted")
	}
}

func TestCleanRelative(t *testing.T) {
	for _, bad := range []string{"../Dockerfile", "/etc/passwd", "a/../../b", ".."} {
		if _, err := cleanRelative(bad, "path"); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
	if got, err := cleanRelative("./docker/Dockerfile.prod", "path"); err != nil || got != "docker/Dockerfile.prod" {
		t.Fatalf("got %q %v", got, err)
	}
}
