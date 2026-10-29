package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"

	"vdxclone/internal/config"
	"vdxclone/internal/imageio"
	"vdxclone/internal/ovirtapi"
	"vdxclone/internal/secrets"
	"vdxclone/internal/service"
	"vdxclone/internal/vmbackup"
)

// startOvirt brings up the optional oVirt-compatible backup API ([ovirt]):
// the engine listener (SSO, REST, /images/) and the imageio data listener,
// both TLS with a per-install CA, both bound to a specific address. It
// returns the servers to shut down, or an error and opens nothing.
func startOvirt(ctx context.Context, cfg *config.Config, svc *service.Service, nodeName string) ([]*http.Server, error) {
	apiAddr, ioAddr, err := cfg.OvirtAddrs()
	if err != nil {
		return nil, err
	}
	apiHost, apiPort, _ := net.SplitHostPort(apiAddr)
	ioHost, ioPort, _ := net.SplitHostPort(ioAddr)
	public := cfg.Ovirt.PublicHost
	if public == "" {
		public = apiHost
	}
	dir := cfg.Paths.DataDir
	ca, err := secrets.LoadOrCreateCA(filepath.Join(dir, "ovirt-ca.crt"), filepath.Join(dir, "ovirt-ca.key"),
		"VXVisor backup API CA ("+nodeName+")")
	if err != nil {
		return nil, fmt.Errorf("backup API CA: %w", err)
	}
	cert, err := ca.LoadOrIssue(filepath.Join(dir, "ovirt-tls.crt"), filepath.Join(dir, "ovirt-tls.key"),
		[]string{public, apiHost, ioHost})
	if err != nil {
		return nil, fmt.Errorf("backup API certificate: %w", err)
	}
	work := cfg.Ovirt.WorkDir
	if work == "" {
		work = filepath.Join(dir, "backup-work")
	}
	if len(work) > vmbackup.MaxWorkRootLen {
		// NBD unix sockets live under it and must fit sun_path.
		return nil, fmt.Errorf("[ovirt] work_dir %q is longer than %d bytes", work, vmbackup.MaxWorkRootLen)
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, fmt.Errorf("backup work dir: %w", err)
	}

	be := svc.NewOvirtBackend(public)
	be.RecoverBackups(work) // whatever a crashed vdxd left in QEMU or as qemu-nbd

	ap, _ := strconv.Atoi(apiPort)
	ip, _ := strconv.Atoi(ioPort)
	io := imageio.NewServer()
	eng := ovirtapi.New(ovirtapi.Config{
		PublicHost: public, APIPort: ap, ImageioPort: ip, WorkRoot: work, CAPEM: ca.PEM,
		InstanceID:  uuid.NewSHA1(uuid.NameSpaceOID, []byte("vxvisor-ovirt-engine:"+nodeName)).String(),
		NodeName:    nodeName,
		ProductName: cfg.Ovirt.ProductName,
	}, be, io)

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	var servers []*http.Server
	var listeners []net.Listener
	for _, l := range []struct {
		addr string
		h    http.Handler
	}{{apiAddr, eng.Handler()}, {ioAddr, eng.ImageioHandler()}} {
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			for _, o := range listeners {
				_ = o.Close()
			}
			return nil, fmt.Errorf("backup API listen %s: %w", l.addr, err)
		}
		listeners = append(listeners, ln)
		// No write/read timeouts: an image transfer streams for as long as
		// the disk takes; the imageio tickets' inactivity timeouts bound idle.
		servers = append(servers, &http.Server{Handler: l.h, TLSConfig: tlsCfg, ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout: 5 * time.Minute})
	}
	go eng.Run(ctx)
	for i, srv := range servers {
		srv, ln := srv, tls.NewListener(listeners[i], tlsCfg)
		go func() {
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("backup API listener error: %v", err)
			}
		}()
	}
	log.Printf("oVirt-compatible backup API listening on %s (imageio %s), public host %s", apiAddr, ioAddr, public)
	return servers, nil
}
