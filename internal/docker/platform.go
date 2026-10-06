package docker

// The Engine API calls a managed database needs beyond services: the nodes
// of the Swarm (to pin a data node to one), overlay networks of its own,
// Swarm configs and secrets (the files a router or pooler mounts), one-off
// containers (a client that runs SQL from stdin, a probe), and the removal
// of a data volume on this node. Nothing here reads the host: no bind
// mounts, no exec into a running container, no privileged option.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// -- nodes ----------------------------------------------------------------------

// Node is the part of GET /nodes a placement decision needs.
type Node struct {
	ID   string `json:"ID"`
	Spec struct {
		Role         string `json:"Role"`
		Availability string `json:"Availability"`
	} `json:"Spec"`
	Description struct {
		Hostname string `json:"Hostname"`
	} `json:"Description"`
	Status struct {
		State string `json:"State"`
	} `json:"Status"`
}

// ListNodes lists the Swarm's nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	var out []Node
	if err := c.do(ctx, http.MethodGet, "/nodes", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// -- networks -------------------------------------------------------------------

// CreateOverlay creates an attachable Swarm overlay network and returns its
// id. Attachable, so a one-off client container can join it; unencrypted,
// like the ones the platform makes (see the provisioner).
func (c *Client) CreateOverlay(ctx context.Context, name string, labels map[string]string) (string, error) {
	body := map[string]any{
		"Name": name, "Driver": "overlay", "Scope": "swarm", "Attachable": true, "Labels": labels,
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := c.do(ctx, http.MethodPost, "/networks/create", nil, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// RemoveNetwork deletes a network.
func (c *Client) RemoveNetwork(ctx context.Context, idOrName string) error {
	return c.do(ctx, http.MethodDelete, "/networks/"+idOrName, nil, nil, nil)
}

// -- configs and secrets ----------------------------------------------------------

// SwarmObject is a Swarm config or secret as listed.
type SwarmObject struct {
	ID   string `json:"ID"`
	Spec struct {
		Name   string            `json:"Name"`
		Labels map[string]string `json:"Labels"`
	} `json:"Spec"`
}

// CreateConfig stores a file for services to mount read-only.
func (c *Client) CreateConfig(ctx context.Context, name string, data []byte, labels map[string]string) (string, error) {
	return c.createObject(ctx, "/configs/create", name, data, labels)
}

// CreateSecret stores a file the scheduler delivers on a tmpfs: for content
// that must not sit in the Raft log in clear the way a config does.
func (c *Client) CreateSecret(ctx context.Context, name string, data []byte, labels map[string]string) (string, error) {
	return c.createObject(ctx, "/secrets/create", name, data, labels)
}

func (c *Client) createObject(ctx context.Context, path, name string, data []byte, labels map[string]string) (string, error) {
	body := map[string]any{"Name": name, "Labels": labels, "Data": base64.StdEncoding.EncodeToString(data)}
	var out struct {
		ID string `json:"ID"`
	}
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ListConfigs lists the configs carrying a label.
func (c *Client) ListConfigs(ctx context.Context, label string) ([]SwarmObject, error) {
	var out []SwarmObject
	if err := c.do(ctx, http.MethodGet, "/configs", filters(map[string][]string{"label": {label}}), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListSecrets lists the secrets carrying a label.
func (c *Client) ListSecrets(ctx context.Context, label string) ([]SwarmObject, error) {
	var out []SwarmObject
	if err := c.do(ctx, http.MethodGet, "/secrets", filters(map[string][]string{"label": {label}}), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveConfig deletes a config; the engine refuses while a service uses it.
func (c *Client) RemoveConfig(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/configs/"+id, nil, nil, nil)
}

// RemoveSecret deletes a secret; the engine refuses while a service uses it.
func (c *Client) RemoveSecret(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/secrets/"+id, nil, nil, nil)
}

// -- volumes --------------------------------------------------------------------

// Volume is the part of GET /volumes/{name} the agent checks before removing.
type Volume struct {
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

// InspectVolume fetches one local volume.
func (c *Client) InspectVolume(ctx context.Context, name string) (*Volume, error) {
	var v Volume
	if err := c.do(ctx, http.MethodGet, "/volumes/"+name, nil, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// RemoveVolume deletes a local volume; the engine refuses one still in use.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/volumes/"+name, nil, nil, nil)
}

// -- one-off containers -----------------------------------------------------------

// JobSpec is one container run to completion on this node.
type JobSpec struct {
	Image   string
	Command []string
	Env     []string
	// An attachable overlay the container joins; empty for none.
	Network string
	// Fed to the process on stdin and then closed, so a script or a password
	// never appears on a command line.
	Stdin   string
	Labels  map[string]string
	Timeout time.Duration
}

// JobResult is what the container left behind.
type JobResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	TimedOut bool
}

// Bounds on a job's output kept for the reply.
const maxJobOutput = 200 << 10

// RunJob creates the container, feeds its stdin, waits for it to exit, reads
// what it printed and removes it. The image is pulled when this node does
// not have it. `--rm`, in Engine API terms.
func (c *Client) RunJob(ctx context.Context, spec JobSpec) (*JobResult, error) {
	hasStdin := spec.Stdin != ""
	body := map[string]any{
		"Image":       spec.Image,
		"Cmd":         spec.Command,
		"Env":         spec.Env,
		"Labels":      spec.Labels,
		"OpenStdin":   hasStdin,
		"StdinOnce":   hasStdin,
		"AttachStdin": hasStdin,
		"HostConfig":  map[string]any{"NetworkMode": orDefault(spec.Network, "none")},
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	q := url.Values{"name": {"isogrid-job-" + hex.EncodeToString(suffix)}}
	var created struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, http.MethodPost, "/containers/create", q, body, &created)
	if IsNotFound(err) {
		// The image, not the network: the daemon says 404 for both, and a
		// missing network is reported with its name in the message.
		if strings.Contains(strings.ToLower(errorMessage(err)), "network") {
			return nil, err
		}
		if perr := c.pull(ctx, spec.Image); perr != nil {
			return nil, perr
		}
		err = c.do(ctx, http.MethodPost, "/containers/create", q, body, &created)
	}
	if err != nil {
		return nil, err
	}
	id := created.ID
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = c.do(cleanup, http.MethodDelete, "/containers/"+id, url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	}()

	if err := c.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil); err != nil {
		return nil, err
	}
	attachErr := make(chan error, 1)
	if hasStdin {
		go func() { attachErr <- c.feedStdin(ctx, id, []byte(spec.Stdin)) }()
	} else {
		attachErr <- nil
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var waited struct {
		StatusCode int `json:"StatusCode"`
	}
	result := &JobResult{}
	werr := c.do(waitCtx, http.MethodPost, "/containers/"+id+"/wait", nil, nil, &waited)
	switch {
	case werr == nil:
		result.ExitCode = waited.StatusCode
	case errors.Is(waitCtx.Err(), context.DeadlineExceeded):
		kill, kcancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = c.do(kill, http.MethodPost, "/containers/"+id+"/kill", nil, nil, nil)
		kcancel()
		result.ExitCode, result.TimedOut = 124, true
	default:
		return nil, werr
	}
	if aerr := <-attachErr; aerr != nil && werr == nil && result.ExitCode != 0 {
		// Only worth reporting when the job also failed: a process that
		// exits before reading all of its stdin closes the pipe on us.
		result.Stderr = "stdin: " + aerr.Error() + "\n"
	}

	stdout, stderr := c.containerOutput(ctx, id)
	result.Stdout += stdout
	result.Stderr += stderr
	if result.TimedOut {
		result.Stderr += fmt.Sprintf("the job did not finish within %s and was killed\n", timeout)
	}
	return result, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func errorMessage(err error) string {
	var de *Error
	if errors.As(err, &de) {
		return de.Message
	}
	return err.Error()
}

// pull fetches an image, following the daemon's progress to its end so an
// error in the stream is surfaced rather than a half-pulled image used.
func (c *Client) pull(ctx context.Context, image string) error {
	from, tag := image, ""
	if !strings.Contains(image, "@") {
		if slash := strings.LastIndex(image, "/"); strings.LastIndex(image, ":") > slash {
			from, tag = image[:strings.LastIndex(image, ":")], image[strings.LastIndex(image, ":")+1:]
		}
	}
	q := url.Values{"fromImage": {from}}
	if tag != "" {
		q.Set("tag", tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/images/create?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Status: 0, Message: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	return follow(resp.Body, io.Discard, func(json.RawMessage) {})
}

// feedStdin hands the data to the container's stdin over a hijacked attach
// and half-closes the stream, which is how the process sees end of file.
// Attaching after start is fine: with StdinOnce the container's stdin stays
// open until a client has attached and gone.
func (c *Client) feedStdin(ctx context.Context, id string, data []byte) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	request := fmt.Sprintf(
		"POST /%s/containers/%s/attach?stdin=1&stream=1 HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
		APIVersion, id, c.hostHeader,
	)
	if _, err := io.WriteString(conn, request); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return fmt.Errorf("attach: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &Error{Status: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = half.CloseWrite()
	}
	// Hold the stream until the daemon ends it (the container exited), so
	// the data is not discarded with an early close.
	_, _ = io.Copy(io.Discard, reader)
	return nil
}

// containerOutput reads everything a finished container printed.
func (c *Client) containerOutput(ctx context.Context, id string) (stdout, stderr string) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/containers/"+id+"/logs?"+q.Encode(), nil)
	if err != nil {
		return "", ""
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", ""
	}
	lines := demux(bufio.NewReaderSize(io.LimitReader(resp.Body, maxLogBytes), 64<<10))
	var out, errs bytes.Buffer
	for _, line := range lines {
		target := &out
		if line.Stream == "stderr" {
			target = &errs
		}
		if target.Len() > maxJobOutput {
			continue
		}
		target.WriteString(line.Text)
		target.WriteByte('\n')
	}
	return out.String(), errs.String()
}
