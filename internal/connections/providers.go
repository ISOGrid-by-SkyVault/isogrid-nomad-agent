package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Repository is one code repository as ISOGrid may see it: its name.
type Repository struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Private       bool   `json:"private"`
}

// Refs are the branches and tags of a repository.
type Refs struct {
	DefaultBranch string   `json:"default_branch,omitempty"`
	Branches      []string `json:"branches"`
	Tags          []string `json:"tags"`
}

// Commit is one commit: id, first line, author name and date. No diff.
type Commit struct {
	SHA    string `json:"sha"`
	Title  string `json:"title"`
	Author string `json:"author,omitempty"`
	Date   string `json:"date,omitempty"`
}

// Images is what a registry lists: repositories, or the tags of one.
type Images struct {
	Repositories []string `json:"repositories,omitempty"`
	Repository   string   `json:"repository,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

const pageSize = 50

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	if len(line) > 160 {
		line = line[:160]
	}
	return line
}

// -- GitHub --------------------------------------------------------------------------

func githubAPI(c *Connection) string {
	if c.Host == "github.com" {
		return "https://api.github.com"
	}
	return "https://" + c.Host + "/api/v3"
}

func (m *Manager) github(ctx context.Context, c *Connection, token, path string, out any) error {
	return m.getJSON(ctx, githubAPI(c)+path, map[string]string{
		"Authorization":        "Bearer " + token,
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}, out)
}

// -- GitLab --------------------------------------------------------------------------

func (m *Manager) gitlab(ctx context.Context, c *Connection, token, path string, out any) error {
	return m.getJSON(ctx, "https://"+c.Host+"/api/v4"+path, map[string]string{"PRIVATE-TOKEN": token}, out)
}

// -- code hosts, by operation --------------------------------------------------------

// Repositories lists what the connection's token can see, most recently
// active first, one page at a time, optionally filtered by a substring.
func (m *Manager) Repositories(ctx context.Context, name, query string, page int) ([]Repository, error) {
	c, token, err := m.load(ctx, name, KindGitHub, KindGitLab)
	if err != nil {
		return nil, err
	}
	if page < 1 || page > 200 {
		page = 1
	}
	query = strings.TrimSpace(query)
	if len(query) > 80 {
		query = query[:80]
	}
	out := []Repository{}
	if c.Kind == KindGitHub {
		var rows []struct {
			FullName      string `json:"full_name"`
			DefaultBranch string `json:"default_branch"`
			Private       bool   `json:"private"`
		}
		if err := m.github(ctx, c, token, fmt.Sprintf("/user/repos?per_page=%d&page=%d&sort=pushed", pageSize, page), &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			if query == "" || strings.Contains(strings.ToLower(r.FullName), strings.ToLower(query)) {
				out = append(out, Repository{FullName: r.FullName, DefaultBranch: r.DefaultBranch, Private: r.Private})
			}
		}
		return out, nil
	}
	var rows []struct {
		Path          string `json:"path_with_namespace"`
		DefaultBranch string `json:"default_branch"`
		Visibility    string `json:"visibility"`
	}
	path := fmt.Sprintf("/projects?membership=true&simple=true&per_page=%d&page=%d&order_by=last_activity_at", pageSize, page)
	if query != "" {
		path += "&search=" + url.QueryEscape(query)
	}
	if err := m.gitlab(ctx, c, token, path, &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, Repository{FullName: r.Path, DefaultBranch: r.DefaultBranch, Private: r.Visibility != "public"})
	}
	return out, nil
}

type named struct {
	Name string `json:"name"`
}

func names(rows []named) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

// Refs lists a repository's branches and tags.
func (m *Manager) Refs(ctx context.Context, name, repo string) (*Refs, error) {
	c, token, err := m.load(ctx, name, KindGitHub, KindGitLab)
	if err != nil {
		return nil, err
	}
	if repo, err = CleanRepository(repo); err != nil {
		return nil, err
	}
	var branches, tags []named
	refs := &Refs{}
	if c.Kind == KindGitHub {
		var info struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := m.github(ctx, c, token, "/repos/"+repo, &info); err != nil {
			return nil, err
		}
		refs.DefaultBranch = info.DefaultBranch
		if err := m.github(ctx, c, token, "/repos/"+repo+"/branches?per_page=100", &branches); err != nil {
			return nil, err
		}
		if err := m.github(ctx, c, token, "/repos/"+repo+"/tags?per_page=50", &tags); err != nil {
			return nil, err
		}
	} else {
		id := url.PathEscape(repo)
		var info struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := m.gitlab(ctx, c, token, "/projects/"+id, &info); err != nil {
			return nil, err
		}
		refs.DefaultBranch = info.DefaultBranch
		if err := m.gitlab(ctx, c, token, "/projects/"+id+"/repository/branches?per_page=100", &branches); err != nil {
			return nil, err
		}
		if err := m.gitlab(ctx, c, token, "/projects/"+id+"/repository/tags?per_page=50", &tags); err != nil {
			return nil, err
		}
	}
	refs.Branches, refs.Tags = names(branches), names(tags)
	return refs, nil
}

// Commits lists the latest commits of a branch or tag.
func (m *Manager) Commits(ctx context.Context, name, repo, ref string) ([]Commit, error) {
	c, token, err := m.load(ctx, name, KindGitHub, KindGitLab)
	if err != nil {
		return nil, err
	}
	if repo, err = CleanRepository(repo); err != nil {
		return nil, err
	}
	if ref, err = CleanRef(ref); err != nil {
		return nil, err
	}
	out := []Commit{}
	if c.Kind == KindGitHub {
		var rows []struct {
			SHA    string `json:"sha"`
			Commit struct {
				Message string `json:"message"`
				Author  struct {
					Name string `json:"name"`
					Date string `json:"date"`
				} `json:"author"`
			} `json:"commit"`
		}
		if err := m.github(ctx, c, token, "/repos/"+repo+"/commits?per_page=20&sha="+url.QueryEscape(ref), &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			out = append(out, Commit{SHA: r.SHA, Title: firstLine(r.Commit.Message), Author: r.Commit.Author.Name, Date: r.Commit.Author.Date})
		}
		return out, nil
	}
	var rows []struct {
		ID     string `json:"id"`
		Title  string `json:"title"`
		Author string `json:"author_name"`
		Date   string `json:"committed_date"`
	}
	if err := m.gitlab(ctx, c, token, "/projects/"+url.PathEscape(repo)+"/repository/commits?per_page=20&ref_name="+url.QueryEscape(ref), &rows); err != nil {
		return nil, err
	}
	for _, r := range rows {
		out = append(out, Commit{SHA: r.ID, Title: firstLine(r.Title), Author: r.Author, Date: r.Date})
	}
	return out, nil
}

// Source is a repository at one commit, as a gzipped tar the host produced.
type Source struct {
	Commit  string
	Archive io.ReadCloser
}

// maxArchive bounds the source a build downloads.
const maxArchive = 1 << 30

// Archive resolves a ref to its commit and opens the source archive of that
// exact commit. The code goes from the customer's host to the customer's
// engine; it does not pass through ISOGrid.
func (m *Manager) Archive(ctx context.Context, name, repo, ref string) (*Source, error) {
	c, token, err := m.load(ctx, name, KindGitHub, KindGitLab)
	if err != nil {
		return nil, err
	}
	if repo, err = CleanRepository(repo); err != nil {
		return nil, err
	}
	if ref, err = CleanRef(ref); err != nil {
		return nil, err
	}
	var target string
	headers := map[string]string{}
	var sha string
	if c.Kind == KindGitHub {
		var commit struct {
			SHA string `json:"sha"`
		}
		if err := m.github(ctx, c, token, "/repos/"+repo+"/commits/"+url.PathEscape(ref), &commit); err != nil {
			return nil, err
		}
		sha = commit.SHA
		target = githubAPI(c) + "/repos/" + repo + "/tarball/" + sha
		headers["Authorization"] = "Bearer " + token
		headers["Accept"] = "application/vnd.github+json"
	} else {
		id := url.PathEscape(repo)
		var commit struct {
			ID string `json:"id"`
		}
		if err := m.gitlab(ctx, c, token, "/projects/"+id+"/repository/commits/"+url.PathEscape(ref), &commit); err != nil {
			return nil, err
		}
		sha = commit.ID
		target = "https://" + c.Host + "/api/v4/projects/" + id + "/repository/archive.tar.gz?sha=" + sha
		headers["PRIVATE-TOKEN"] = token
	}
	if sha == "" {
		return nil, fmt.Errorf("%s did not resolve %q to a commit", c.Host, ref)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "isogrid-nomad-agent")
	// No overall timeout: a large repository takes what it takes, bounded by
	// the build's own context.
	client := &http.Client{Transport: m.http.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s did not answer: %w", c.Host, scrub(err))
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, statusError(c.Host, resp)
	}
	return &Source{Commit: sha, Archive: struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, maxArchive), resp.Body}}, nil
}

// -- registries ----------------------------------------------------------------------

func registryBase(c *Connection) string {
	if c.Host == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + c.Host
}

var challengeParam = regexp.MustCompile(`(realm|service|scope)="([^"]*)"`)

// registryGet performs a Registry v2 GET, following the token challenge the
// registry answers an anonymous request with.
func (m *Manager) registryGet(ctx context.Context, c *Connection, secret, path string, out any) error {
	target := registryBase(c) + path
	do := func(authorization string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		req.Header.Set("User-Agent", "isogrid-nomad-agent")
		return m.http.Do(req)
	}
	basic := ""
	if c.Username != "" {
		basic = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+secret))
	}
	resp, err := do("")
	if err != nil {
		return fmt.Errorf("%s did not answer: %w", c.Host, scrub(err))
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		resp.Body.Close()
		authorization := basic
		if strings.HasPrefix(strings.ToLower(challenge), "bearer") {
			params := map[string]string{}
			for _, match := range challengeParam.FindAllStringSubmatch(challenge, -1) {
				params[match[1]] = match[2]
			}
			realm, err := url.Parse(params["realm"])
			if err != nil || realm.Scheme != "https" {
				return fmt.Errorf("%s sent a token service the agent will not use", c.Host)
			}
			q := realm.Query()
			if params["service"] != "" {
				q.Set("service", params["service"])
			}
			if params["scope"] != "" {
				q.Set("scope", params["scope"])
			}
			realm.RawQuery = q.Encode()
			headers := map[string]string{}
			if basic != "" {
				headers["Authorization"] = basic
			}
			var token struct {
				Token       string `json:"token"`
				AccessToken string `json:"access_token"`
			}
			if err := m.getJSON(ctx, realm.String(), headers, &token); err != nil {
				return err
			}
			if token.Token == "" {
				token.Token = token.AccessToken
			}
			authorization = "Bearer " + token.Token
		}
		if authorization == "" {
			return fmt.Errorf("%s wants credentials and the connection has no username", c.Host)
		}
		if resp, err = do(authorization); err != nil {
			return fmt.Errorf("%s did not answer: %w", c.Host, scrub(err))
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(c.Host, resp)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(out); err != nil {
		return fmt.Errorf("%s sent an answer the agent could not read", c.Host)
	}
	return nil
}

func (m *Manager) registryPing(ctx context.Context, c *Connection, secret string) error {
	return m.registryGet(ctx, c, secret, "/v2/", nil)
}

// Images lists a registry's repositories, or the tags of one repository.
func (m *Manager) Images(ctx context.Context, name, repo string) (*Images, error) {
	c, secret, err := m.load(ctx, name, KindRegistry)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(repo) == "" {
		var catalog struct {
			Repositories []string `json:"repositories"`
		}
		if err := m.registryGet(ctx, c, secret, "/v2/_catalog?n=200", &catalog); err != nil {
			if c.Host == "docker.io" {
				return nil, errors.New("Docker Hub does not list repositories; name one to see its tags")
			}
			return nil, err
		}
		sort.Strings(catalog.Repositories)
		return &Images{Repositories: catalog.Repositories}, nil
	}
	if repo, err = CleanRepository(strings.ToLower(repo)); err != nil {
		return nil, err
	}
	if c.Host == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	var list struct {
		Tags []string `json:"tags"`
	}
	if err := m.registryGet(ctx, c, secret, "/v2/"+repo+"/tags/list", &list); err != nil {
		return nil, err
	}
	sort.Sort(sort.Reverse(sort.StringSlice(list.Tags)))
	if len(list.Tags) > 200 {
		list.Tags = list.Tags[:200]
	}
	return &Images{Repository: repo, Tags: list.Tags}, nil
}
