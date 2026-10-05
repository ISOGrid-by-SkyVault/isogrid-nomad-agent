package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Container is the part of GET /containers/json the sampler reads.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// ServiceNameLabel is set by Swarm on every container of a service.
const ServiceNameLabel = "com.docker.swarm.service.name"

// RunningContainers lists the running containers on this node that carry a
// label.
func (c *Client) RunningContainers(ctx context.Context, label string) ([]Container, error) {
	var out []Container
	q := filters(map[string][]string{"label": {label}, "status": {"running"}})
	if err := c.do(ctx, http.MethodGet, "/containers/json", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Stats is one reading of a container's counters.
type Stats struct {
	Read time.Time
	// CPUTotal is the container's cumulative CPU time, in nanoseconds.
	CPUTotal uint64
	// Memory is what the container holds, page cache it could give back
	// excluded: the figure `docker stats` shows.
	Memory      uint64
	MemoryLimit uint64
}

// ContainerStats takes one reading without waiting for a second one: the
// caller keeps the previous reading and computes the rate itself.
func (c *Client) ContainerStats(ctx context.Context, id string) (*Stats, error) {
	var raw struct {
		Read     time.Time `json:"read"`
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
		} `json:"cpu_stats"`
		MemoryStats struct {
			Usage uint64            `json:"usage"`
			Limit uint64            `json:"limit"`
			Stats map[string]uint64 `json:"stats"`
		} `json:"memory_stats"`
	}
	q := url.Values{"stream": {"false"}, "one-shot": {"true"}}
	if err := c.do(ctx, http.MethodGet, "/containers/"+id+"/stats", q, nil, &raw); err != nil {
		return nil, err
	}
	memory := raw.MemoryStats.Usage
	// cgroup v2 calls it inactive_file, v1 total_inactive_file.
	for _, key := range []string{"inactive_file", "total_inactive_file"} {
		if cache, ok := raw.MemoryStats.Stats[key]; ok && cache < memory {
			memory -= cache
			break
		}
	}
	if raw.Read.IsZero() {
		raw.Read = time.Now()
	}
	return &Stats{Read: raw.Read, CPUTotal: raw.CPUStats.CPUUsage.TotalUsage, Memory: memory, MemoryLimit: raw.MemoryStats.Limit}, nil
}

// LogLine is one line a service wrote.
type LogLine struct {
	Time   string `json:"time"`
	Stream string `json:"stream"` // stdout | stderr
	Text   string `json:"text"`
}

// Bounds on one log read: the console asks for a tail, not an archive.
const (
	MaxLogLines = 2000
	maxLogBytes = 4 << 20
	maxLineLen  = 16 << 10
)

// ServiceLogs returns the last lines a service wrote, oldest first. `since`,
// when not zero, drops what is older. The engine keeps these logs; they are
// read on demand and never leave this process except to the console.
func (c *Client) ServiceLogs(ctx context.Context, idOrName string, tail int, since time.Time) ([]LogLine, error) {
	if tail <= 0 || tail > MaxLogLines {
		tail = MaxLogLines
	}
	q := url.Values{"stdout": {"true"}, "stderr": {"true"}, "timestamps": {"true"}, "tail": {strconv.Itoa(tail)}}
	if !since.IsZero() {
		q.Set("since", strconv.FormatInt(since.Unix(), 10))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/services/"+idOrName+"/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &Error{Status: 0, Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = json.Unmarshal(raw, &msg)
		if msg.Message == "" {
			msg.Message = strings.TrimSpace(string(raw))
		}
		return nil, &Error{Status: resp.StatusCode, Message: msg.Message}
	}
	lines := demux(bufio.NewReaderSize(io.LimitReader(resp.Body, maxLogBytes), 64<<10))
	// The engine returns `tail` lines per task; keep the newest overall.
	sortByTime(lines)
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines, nil
}

// demux reads the engine's multiplexed log stream: frames of an 8-byte
// header (stream, three zero bytes, big-endian length) and a payload. A
// service with a TTY sends plain text instead; that is read line by line.
func demux(r *bufio.Reader) []LogLine {
	lines := []LogLine{}
	head, err := r.Peek(8)
	framed := err == nil && head[0] <= 2 && head[1] == 0 && head[2] == 0 && head[3] == 0
	if !framed {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64<<10), maxLineLen)
		for scanner.Scan() {
			lines = append(lines, splitLine("stdout", scanner.Text()))
		}
		return lines
	}
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return lines
		}
		size := binary.BigEndian.Uint32(header[4:8])
		payload := make([]byte, min(size, maxLineLen))
		if _, err := io.ReadFull(r, payload); err != nil {
			return lines
		}
		if size > maxLineLen {
			if _, err := io.CopyN(io.Discard, r, int64(size-maxLineLen)); err != nil {
				return lines
			}
		}
		stream := "stdout"
		if header[0] == 2 {
			stream = "stderr"
		}
		for _, text := range strings.Split(strings.TrimRight(string(payload), "\n"), "\n") {
			lines = append(lines, splitLine(stream, text))
		}
	}
}

func splitLine(stream, text string) LogLine {
	text = strings.TrimRight(text, "\r")
	if at, rest, ok := strings.Cut(text, " "); ok && len(at) >= 20 && at[4] == '-' && strings.HasSuffix(at, "Z") {
		return LogLine{Time: at, Stream: stream, Text: rest}
	}
	return LogLine{Stream: stream, Text: text}
}

// sortByTime orders lines by their RFC 3339 timestamps, which sort as text.
// A line without one sorts with the line before it.
func sortByTime(lines []LogLine) {
	keys := make([]string, len(lines))
	last := ""
	for i, l := range lines {
		if l.Time != "" {
			last = l.Time
		}
		keys[i] = last
	}
	order := make([]int, len(lines))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return keys[order[a]] < keys[order[b]] })
	sorted := make([]LogLine, len(lines))
	for i, j := range order {
		sorted[i] = lines[j]
	}
	copy(lines, sorted)
}
