package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BuildOptions describe one image build.
type BuildOptions struct {
	Tag        string            // full image reference the result gets
	Dockerfile string            // path inside the context, default Dockerfile
	Labels     map[string]string // recorded on the image
	Pull       bool              // refresh base images
}

// progress is one line of the engine's build or push output.
type progress struct {
	Stream      string `json:"stream"`
	Status      string `json:"status"`
	ID          string `json:"id"`
	Error       string `json:"error"`
	ErrorDetail struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
	Aux json.RawMessage `json:"aux"`
}

// follow copies the engine's progress to `log` and returns the first error
// it reports; `aux` receives the structured results (image id, digest).
func follow(body io.Reader, log io.Writer, aux func(json.RawMessage)) error {
	reader := bufio.NewReaderSize(body, 64<<10)
	dec := json.NewDecoder(reader)
	var failure error
	lastStatus := ""
	for {
		var p progress
		if err := dec.Decode(&p); err != nil {
			if errors.Is(err, io.EOF) {
				return failure
			}
			if failure != nil {
				return failure
			}
			return fmt.Errorf("the engine's output stopped: %w", err)
		}
		switch {
		case p.Error != "" || p.ErrorDetail.Message != "":
			message := p.ErrorDetail.Message
			if message == "" {
				message = p.Error
			}
			fmt.Fprintf(log, "ERROR: %s\n", message)
			if failure == nil {
				failure = errors.New(strings.TrimSpace(message))
			}
		case p.Stream != "":
			_, _ = io.WriteString(log, p.Stream)
		case p.Status != "":
			// Layer progress repeats; write a status once per change.
			line := p.Status
			if p.ID != "" {
				line = p.ID + ": " + line
			}
			if line != lastStatus && !noisy(p.Status) {
				fmt.Fprintln(log, line)
			}
			lastStatus = line
		}
		if len(p.Aux) > 0 && aux != nil {
			aux(p.Aux)
		}
	}
}

// noisy reports the per-layer progress statuses that repeat many times a
// second and say nothing in a log.
func noisy(status string) bool {
	for _, prefix := range []string{"Downloading", "Extracting", "Pushing", "Waiting", "Preparing", "Verifying Checksum"} {
		if status == prefix || strings.HasPrefix(status, prefix+" ") {
			return true
		}
	}
	return false
}

// Build sends a tar build context to the engine and waits for the image.
// Everything the build prints goes to `log`.
func (c *Client) Build(ctx context.Context, buildContext io.Reader, opt BuildOptions, log io.Writer) error {
	q := url.Values{"t": {opt.Tag}, "rm": {"1"}, "forcerm": {"1"}}
	if opt.Dockerfile != "" {
		q.Set("dockerfile", opt.Dockerfile)
	}
	if opt.Pull {
		q.Set("pull", "1")
	}
	if len(opt.Labels) > 0 {
		labels, _ := json.Marshal(opt.Labels)
		q.Set("labels", string(labels))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/build?"+q.Encode(), buildContext)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineError(resp)
	}
	return follow(resp.Body, log, nil)
}

// Push sends an image to its registry and returns the digest it got there.
func (c *Client) Push(ctx context.Context, image, registryAuth string, log io.Writer) (string, error) {
	name, tag := image, "latest"
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		name, tag = image[:i], image[i+1:]
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/images/"+name+"/push?tag="+url.QueryEscape(tag), nil)
	if err != nil {
		return "", err
	}
	// The engine requires the header even for an anonymous push.
	if registryAuth == "" {
		registryAuth = "e30="
	}
	req.Header.Set("X-Registry-Auth", registryAuth)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", engineError(resp)
	}
	digest := ""
	err = follow(resp.Body, log, func(aux json.RawMessage) {
		var out struct {
			Digest string `json:"Digest"`
		}
		if json.Unmarshal(aux, &out) == nil && out.Digest != "" {
			digest = out.Digest
		}
	})
	return digest, err
}

// ImageInfo is the part of GET /images/{ref}/json the agent uses.
type ImageInfo struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

// Pull brings an image onto this node without touching any service, so a
// later update swaps to layers already on disk. A fleet device that loses
// its link during the pull keeps running what it has; a pull that fails
// changes nothing.
func (c *Client) Pull(ctx context.Context, image, registryAuth string, log io.Writer) error {
	query := url.Values{}
	if strings.Contains(image, "@") {
		query.Set("fromImage", image)
	} else {
		name, tag := image, "latest"
		if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
			name, tag = image[:i], image[i+1:]
		}
		query.Set("fromImage", name)
		query.Set("tag", tag)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/images/create?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	if registryAuth != "" {
		req.Header.Set("X-Registry-Auth", registryAuth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return engineError(resp)
	}
	if log == nil {
		log = io.Discard
	}
	return follow(resp.Body, log, func(json.RawMessage) {})
}

// InspectImage reports an image present on this node; a not-found error
// when it is absent.
func (c *Client) InspectImage(ctx context.Context, ref string) (*ImageInfo, error) {
	var info ImageInfo
	if err := c.do(ctx, http.MethodGet, "/images/"+url.PathEscape(ref)+"/json", nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func engineError(resp *http.Response) error {
	var msg struct {
		Message string `json:"message"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = json.Unmarshal(raw, &msg)
	if msg.Message == "" {
		msg.Message = strings.TrimSpace(string(raw))
	}
	return &Error{Status: resp.StatusCode, Message: msg.Message}
}
