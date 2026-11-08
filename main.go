// cast-relay relays mDNS and SSDP discovery between networks, for selected
// devices only. See SPEC.md. This build implements MODE=observe.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

type settings struct {
	Mode            string
	LogLevel        slog.Level
	ConfigPath      string
	SummaryInterval time.Duration
	Interfaces      []string // optional allowlist of interface names
	Probe           bool
	ProbeInterval   time.Duration
}

func main() {
	s, err := loadSettings()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cast-relay: invalid settings:", err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: s.LogLevel})))
	slog.Info("starting", "version", version, "mode", s.Mode)

	if err := checkNotRouter(); err != nil {
		slog.Error("refusing to start", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch s.Mode {
	case "observe":
		err = runObserve(ctx, s)
	case "relay":
		err = errors.New("relay mode is not implemented in this build; set MODE=observe")
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("stopped", "err", err)
		os.Exit(1)
	}
	slog.Info("stopped")
}

func loadSettings() (settings, error) {
	s := settings{
		Mode:            env("MODE", "relay"),
		ConfigPath:      env("CONFIG", "/config/cast-relay.json"),
		SummaryInterval: 5 * time.Minute,
		Probe:           true,
		ProbeInterval:   time.Minute,
	}
	if s.Mode != "relay" && s.Mode != "observe" {
		return s, fmt.Errorf("MODE=%q: want relay or observe", s.Mode)
	}
	switch v := env("LOG_LEVEL", "info"); v {
	case "info":
		s.LogLevel = slog.LevelInfo
	case "debug":
		s.LogLevel = slog.LevelDebug
	default:
		return s, fmt.Errorf("LOG_LEVEL=%q: want info or debug", v)
	}
	var err error
	if s.SummaryInterval, err = durationEnv("SUMMARY_INTERVAL", s.SummaryInterval); err != nil {
		return s, err
	}
	if s.ProbeInterval, err = durationEnv("OBSERVE_PROBE_INTERVAL", s.ProbeInterval); err != nil {
		return s, err
	}
	switch v := env("OBSERVE_PROBE", "on"); v {
	case "on":
	case "off":
		s.Probe = false
	default:
		return s, fmt.Errorf("OBSERVE_PROBE=%q: want on or off", v)
	}
	if v := env("INTERFACES", ""); v != "" {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				s.Interfaces = append(s.Interfaces, name)
			}
		}
	}
	return s, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func durationEnv(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second {
		return 0, fmt.Errorf("%s=%q: want a duration of at least 1s, e.g. 5m", key, v)
	}
	return d, nil
}

// checkNotRouter refuses to run where IPv4 forwarding is on: a relay with legs
// on several networks must never forward packets between them.
func checkNotRouter() error {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if errors.Is(err, os.ErrNotExist) {
		slog.Warn("cannot check ip_forward (no /proc); assuming a development machine")
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading ip_forward: %w", err)
	}
	if strings.TrimSpace(string(b)) != "0" {
		return errors.New("net.ipv4.ip_forward is enabled in this network namespace; the relay must not be able to route between its networks")
	}
	return nil
}
