package config

import "testing"

// TestOvirtAddrs: the backup API binds a specific IP — derived from [server]
// addr when unset — and never a wildcard.
func TestOvirtAddrs(t *testing.T) {
	cases := []struct {
		server, listen, imageio string
		api, io                 string
		ok                      bool
	}{
		{server: "192.0.2.10:8766", api: "192.0.2.10:443", io: "192.0.2.10:54322", ok: true},
		{server: ":8766", ok: false},
		{server: "0.0.0.0:8766", ok: false},
		{server: ":8766", listen: "192.0.2.10:8443", api: "192.0.2.10:8443", io: "192.0.2.10:54322", ok: true},
		{server: ":8766", listen: "[2001:db8::5]:443", api: "[2001:db8::5]:443", io: "[2001:db8::5]:54322", ok: true},
		{server: ":8766", listen: "127.0.0.1:9443", imageio: "127.0.0.1:9322", api: "127.0.0.1:9443", io: "127.0.0.1:9322", ok: true},
		{server: "192.0.2.10:8766", listen: "0.0.0.0:443", ok: false},
		{server: "192.0.2.10:8766", listen: "[::]:443", ok: false},
		{server: "192.0.2.10:8766", listen: "host.example:443", ok: false},
		{server: "192.0.2.10:8766", imageio: ":54322", ok: false},
	}
	for _, c := range cases {
		cfg := Default()
		cfg.Server.Addr = c.server
		cfg.Ovirt.Listen, cfg.Ovirt.ImageioListen = c.listen, c.imageio
		api, io, err := cfg.OvirtAddrs()
		if (err == nil) != c.ok {
			t.Errorf("%+v: err=%v, want ok=%v", c, err, c.ok)
			continue
		}
		if c.ok && (api != c.api || io != c.io) {
			t.Errorf("%+v: got %s / %s", c, api, io)
		}
	}
	if Default().Ovirt.Enabled {
		t.Error("the backup API must be off by default")
	}
}
