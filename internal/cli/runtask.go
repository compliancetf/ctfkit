package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/spf13/cobra"

	"github.com/compliancetf/ctfkit/adapters/hcp"
	"github.com/compliancetf/ctfkit/internal/catalog"
	"github.com/compliancetf/ctfkit/pkg/ctfkit"
	"github.com/compliancetf/ctfkit/pkg/verdict"
)

const (
	hcpHostname      = "app.terraform.io"
	hcpArchiveHost   = "archivist.terraform.io"
	shutdownGrace    = 10 * time.Second
	defaultPlanBytes = 64 << 20
)

type runtaskOptions struct {
	listen, hmacKeyFile, hostname, receiptDir string
	tlsCert, tlsKey                           string
	org, profile, floor, bundleDir            string
	archiveHosts                              []string
	maxPlanBytes                              int64
	replayWindow, timeout                     time.Duration
	maxConcurrent                             int
}

func (c *CLI) runtaskCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "runtask", Short: "HCP Terraform and Terraform Enterprise run task (preview)"}
	cmd.AddCommand(c.runtaskServeCommand())
	return cmd
}

const runtaskServeLong = `Serve an advisory run task for HCP Terraform or Terraform Enterprise: findings
and a receipt, no verdict (preview). It checks every flag and signed input
before it listens on --listen, and reads .ctfkit.yaml in the working directory.
For each request signed with the key in --hmac-key-file, it downloads the plan
JSON from --hostname (a redirect may go to --archive-host only), runs the
post_plan analyzers of ctfkit scan, writes TASK_RESULT_ID.receipt.json to
--receipt-dir and sends the task result back. It uses the network; plain HTTP
is allowed on a loopback address only.

Refuses to start (exit 2) when:
  - a flag, the HMAC key file or a signed input is refused
  - --listen is not a loopback address and --tls-cert or --tls-key is missing

Exit codes:
  0  stopped by SIGINT or SIGTERM, after the runs in flight finished
  2  could not run, or refused

On exit 2: stderr names the cause. A refusal writes no receipt; a server that
failed while running keeps the receipts of the runs it finished. Fix the flag,
file or address and start it again.

Details: adapters/hcp/README.md`

func (c *CLI) runtaskServeCommand() *cobra.Command {
	opts := &runtaskOptions{listen: "127.0.0.1:8080", hostname: hcpHostname}
	cmd := &cobra.Command{
		Use:   "serve --hmac-key-file FILE --receipt-dir DIR --org ID --profile FILE --floor FILE --bundle-dir DIR",
		Short: "Serve an advisory run task: findings and a receipt, no verdict (preview)",
		Long:  runtaskServeLong,
		Example: `  ctfkit runtask serve --listen 0.0.0.0:8443 --tls-cert tls.crt --tls-key tls.key \
    --hmac-key-file /etc/ctfkit/runtask.key --receipt-dir /var/lib/ctfkit/receipts \
` + signedFlagsLine,
		Args: noArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.runtaskServe(cmd, opts)
		},
	}
	f := cmd.Flags()
	once := func(p *string, name, usage string) { f.Var(&onceString{target: p}, name, usage) }
	once(&opts.listen, "listen", "`ADDRESS` (host:port) to listen on")
	once(&opts.hmacKeyFile, "hmac-key-file", "Absolute path of the run task HMAC key `FILE` (0600, at least 16 bytes)")
	once(&opts.hostname, "hostname", "HCP Terraform or TFE `HOST` every payload URL must be on")
	f.StringArrayVar(&opts.archiveHosts, "archive-host", nil,
		"`HOST` a plan JSON download may be redirected to (default "+hcpArchiveHost+" when --hostname is "+hcpHostname+")")
	once(&opts.receiptDir, "receipt-dir", "Existing `DIR` each run's receipt is written to")
	once(&opts.tlsCert, "tls-cert", "TLS certificate `FILE` (PEM)")
	once(&opts.tlsKey, "tls-key", "TLS private key `FILE` (PEM)")
	once(&opts.org, "org", orgUsage)
	once(&opts.profile, "profile", "Signed org profile `FILE` (DSSE envelope), read again for every run")
	once(&opts.floor, "floor", "Signed floor statement `FILE` (DSSE envelope), read again for every run")
	once(&opts.bundleDir, "bundle-dir", bundleDirUsage)
	f.Int64Var(&opts.maxPlanBytes, "max-plan-bytes", defaultPlanBytes, "Largest plan JSON read, in `BYTES`")
	f.DurationVar(&opts.replayWindow, "replay-window", time.Hour, "How old a run's run_created_at may be, as a `DURATION`")
	f.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "Limit for one run, download to callback, as a `DURATION`; keep it below 10m")
	f.IntVar(&opts.maxConcurrent, "max-concurrent", 4, "`N` runs in flight at once; a request beyond answers 503")
	return cmd
}

// runtaskServe checks every input, then serves until a signal.
func (c *CLI) runtaskServe(cmd *cobra.Command, opts *runtaskOptions) error {
	cfg, err := c.runtaskConfig(cmd, opts)
	if err != nil {
		return err
	}
	h, err := hcp.NewHandler(cfg)
	if err != nil {
		return inputError("runtask serve: %v", err)
	}
	ln, tlsCfg, err := runtaskListener(opts)
	if err != nil {
		_ = h.Close(context.Background())
		return err
	}
	srv := &http.Server{
		Handler: h, TLSConfig: tlsCfg, ErrorLog: cfg.Log,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
		ln = tls.NewListener(ln, tlsCfg)
	}
	cfg.Log.Printf("runtask serve (preview) listening on %s://%s", scheme, ln.Addr())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case err = <-served:
	}
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	err = errors.Join(err, srv.Shutdown(sctx))
	hctx, hcancel := context.WithTimeout(context.Background(), opts.timeout+shutdownGrace)
	defer hcancel()
	err = errors.Join(err, h.Close(hctx))
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return environmentError(fmt.Errorf("runtask serve: %w", err))
	}
	return nil
}

// runtaskConfig reads the key and verifies the signed inputs once, so a bad
// input exits 2 before anything listens.
func (c *CLI) runtaskConfig(cmd *cobra.Command, opts *runtaskOptions) (hcp.Config, error) {
	if err := requireFlags(cmd, flagValue{"hmac-key-file", opts.hmacKeyFile}, flagValue{"receipt-dir", opts.receiptDir},
		flagValue{"org", opts.org}, flagValue{"profile", opts.profile}, flagValue{"floor", opts.floor},
		flagValue{"bundle-dir", opts.bundleDir}); err != nil {
		return hcp.Config{}, err
	}
	key, err := readSecretFile("--hmac-key-file", opts.hmacKeyFile)
	if err != nil {
		return hcp.Config{}, err
	}
	key = bytes.TrimRight(key, "\r\n")
	if st, serr := os.Lstat(opts.receiptDir); serr != nil || !st.IsDir() {
		return hcp.Config{}, inputError("--receipt-dir %s is not a directory; create it or name an existing one", opts.receiptDir)
	}
	archive := opts.archiveHosts
	if len(archive) == 0 && opts.hostname == hcpHostname {
		archive = []string{hcpArchiveHost}
	}
	inputs := &gatePlanOptions{org: opts.org, profile: opts.profile, floor: opts.floor, bundleDir: opts.bundleDir}
	profile := func(now time.Time) (hcp.Profile, error) {
		in, rerr := readGateInputs(c.keyring, inputs)
		if rerr != nil {
			return hcp.Profile{}, fmt.Errorf("reading signed inputs: %w", rerr)
		}
		ver, verr := verdict.VerifyInputs(in, now)
		if verr != nil {
			return hcp.Profile{}, fmt.Errorf("signed inputs refused: %w", verr)
		}
		return hcp.Profile{VerdictRequired: ver.Profile.VerdictRequired, Digest: ver.ProfileDigest}, nil
	}
	if _, err = profile(c.now()); err != nil {
		return hcp.Config{}, inputError("%v", err)
	}
	settings, err := c.loadSettings(".")
	if err != nil {
		return hcp.Config{}, err
	}
	cat, _, err := catalog.Resolve("")
	if err != nil {
		return hcp.Config{}, environmentError(err)
	}
	analyze := func(ctx context.Context, plan *tfjson.Plan, md ctfkit.RunMetadata) (ctfkit.Findings, error) {
		in := ctfkit.AnalyzerInput{Stage: ctfkit.PostPlan, PlanJSON: plan, Catalog: cat,
			Settings: settings.Settings(), Metadata: md}
		findings, aerr := runAnalyzers(ctx, newScanRegistry(), in, nil, cat, md.Now)
		if aerr != nil {
			return nil, aerr
		}
		ctfkit.SortFindings(findings)
		return findings, nil
	}
	return hcp.Config{
		HMACKey: key, Hostname: opts.hostname, ArchiveHosts: archive,
		MaxPlanBytes: opts.maxPlanBytes, ReplayWindow: opts.replayWindow, Timeout: opts.timeout,
		MaxConcurrent: opts.maxConcurrent, ReceiptDir: opts.receiptDir,
		Generator: hcp.Generator{Name: "ctfkit", Version: c.version},
		Transport: c.runtaskTransport, Profile: profile, Analyze: analyze, Now: c.now,
		Log: log.New(cmd.ErrOrStderr(), "ctfkit: ", 0),
	}, nil
}

// runtaskListener listens on --listen. Plain HTTP carries the run's access
// token in the clear, so it is allowed on a loopback address only.
func runtaskListener(opts *runtaskOptions) (net.Listener, *tls.Config, error) {
	if (opts.tlsCert == "") != (opts.tlsKey == "") {
		return nil, nil, inputError("--tls-cert and --tls-key go together")
	}
	var tlsCfg *tls.Config
	if opts.tlsCert != "" {
		pair, err := tls.LoadX509KeyPair(opts.tlsCert, opts.tlsKey)
		if err != nil {
			return nil, nil, inputError("--tls-cert/--tls-key: %v", err)
		}
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}
	ln, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return nil, nil, inputError("--listen %s: %v", opts.listen, err)
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if tlsCfg == nil && (!ok || !addr.IP.IsLoopback()) {
		_ = ln.Close()
		return nil, nil, inputError("--listen %s is not a loopback address, so it needs --tls-cert and --tls-key", opts.listen)
	}
	return ln, tlsCfg, nil
}
