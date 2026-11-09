package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/internal/catalog"
)

// defaultCatalogHost serves the full control catalog to the same token
// terraform uses for compliance.tf modules.
const defaultCatalogHost = "registry.compliance.tf"

// maxCatalogBytes bounds the download; the server refuses to serve more.
const maxCatalogBytes = 8 << 20

// catalogVersionPattern is the name of one published catalog version.
var catalogVersionPattern = regexp.MustCompile(`^\d{4}\.[1-9]\d{2,3}\.(0|[1-9]\d*)$`)

func (c *CLI) catalogCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Download the full control catalog",
	}
	cmd.AddCommand(c.catalogPullCommand())
	return cmd
}

func (c *CLI) catalogPullCommand() *cobra.Command {
	var version, out, host string
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the full control catalog to ~/.ctf/control-requirements.yaml",
		Long: "Download the full control catalog from the compliance.tf registry, verify its\n" +
			"SHA-256 and write it where scan and report read it when --catalog is not given.\n" +
			"It authenticates with the registry token terraform uses: TF_TOKEN_<host>, or\n" +
			"~/.terraform.d/credentials.tfrc.json. The full catalog needs a paid plan; the\n" +
			"catalog built into ctfkit holds the CIS AWS Benchmark v6.0 controls.\n" +
			"This is the one command that needs the network; scan and report stay offline.",
		Example: "  ctfkit catalog pull\n  ctfkit catalog pull --version 2026.1109.0 --out catalog.yaml",
		Args:    noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.catalogPull(cmd, host, version, out)
		},
	}
	f := cmd.Flags()
	f.StringVar(&version, "version", "", "catalog `VERSION` to download (default: the latest)")
	f.StringVar(&out, "out", "", "write to `FILE` (default: ~/.ctf/control-requirements.yaml)")
	f.StringVar(&host, "host", defaultCatalogHost, "registry `HOST` to download from")
	return cmd
}

func (c *CLI) catalogPull(cmd *cobra.Command, host, version, out string) error {
	file := "latest.yaml"
	if version != "" {
		if !catalogVersionPattern.MatchString(version) {
			return inputError("--version %q is not a catalog version such as 2026.1109.0", version)
		}
		file = version + ".yaml"
	}
	if out == "" {
		home, err := catalog.HomePath()
		if err != nil {
			return environmentError(err)
		}
		out = home
	}

	token, err := registryToken(host)
	if err != nil {
		return categorized(categoryCatalog, "%v", err)
	}

	body, err := c.fetchCatalog(host, file, token)
	if err != nil {
		return categorized(categoryCatalog, "%v", err)
	}
	got, err := catalog.Validate(body)
	if err != nil {
		return environmentError(fmt.Errorf("downloaded catalog: %w", err))
	}
	if err := writeAtomic(out, body); err != nil {
		return categorized(categoryCatalog, "writing %s: %v", out, err)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "catalog %s written to %s\n", got, out)
	return nil
}

// fetchCatalog downloads one catalog file and checks it against the
// X-Catalog-Sha256 header the server computes over the bytes it sends.
func (c *CLI) fetchCatalog(host, file, token string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/v1/catalog/"+file, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "ctfkit/"+c.version)

	client := &http.Client{Timeout: 60 * time.Second, Transport: c.catalogTransport}
	resp, err := client.Do(req)
	if err != nil {
		// The error names the URL only; the token is in a header, never in it.
		return nil, fmt.Errorf("downloading the catalog from %s: %w", host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCatalogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading the catalog from %s: %w", host, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d: %s", host, resp.StatusCode, serverMessage(body))
	}
	if len(body) > maxCatalogBytes {
		return nil, fmt.Errorf("the catalog from %s is larger than %d bytes", host, maxCatalogBytes)
	}
	want := strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Catalog-Sha256")))
	sum := sha256.Sum256(body)
	if want == "" || want != hex.EncodeToString(sum[:]) {
		return nil, errors.New("the downloaded catalog does not match its X-Catalog-Sha256 header; nothing was written")
	}
	return body, nil
}

// serverMessage is the error text of a refusal, or a short excerpt when the
// body is not the JSON the registry sends.
func serverMessage(body []byte) string {
	var e struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil {
		if e.Error != "" {
			return e.Error
		}
		if e.Message != "" {
			return e.Message
		}
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// registryToken finds the token terraform would send to host: the
// TF_TOKEN_<host> environment variable first, then the credentials file
// terraform login writes.
// shortcut: credentials blocks in a terraform CLI config file (HCL) are not read; add when a user needs them.
func registryToken(host string) (string, error) {
	if t := os.Getenv(tokenEnvName(host)); t != "" {
		return t, nil
	}
	home, err := os.UserHomeDir()
	if err == nil {
		path := filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
		b, readErr := os.ReadFile(path) // #nosec G304 -- the operator's own terraform credentials file
		if readErr == nil {
			var f struct {
				Credentials map[string]struct {
					Token string `json:"token"`
				} `json:"credentials"`
			}
			if jsonErr := json.Unmarshal(b, &f); jsonErr != nil {
				return "", fmt.Errorf("%s does not parse: %w", path, jsonErr)
			}
			if t := f.Credentials[host].Token; t != "" {
				return t, nil
			}
		} else if !errors.Is(readErr, fs.ErrNotExist) {
			return "", fmt.Errorf("reading %s: %w", path, readErr)
		}
	}
	return "", fmt.Errorf("no registry token for %s: set %s or run terraform login %s",
		host, tokenEnvName(host), host)
}

// tokenEnvName is terraform's variable name for a host's token: dots become
// underscores and dashes double underscores.
func tokenEnvName(host string) string {
	return "TF_TOKEN_" + strings.NewReplacer(".", "_", "-", "__").Replace(host)
}

// writeAtomic replaces path with b so a reader never sees half a catalog.
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".catalog-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // #nosec G302 -- the catalog is not secret
		return err
	}
	return os.Rename(tmp.Name(), path)
}
