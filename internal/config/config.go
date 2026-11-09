// Package config loads and validates the tspackages configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Tailscale  Tailscale            `yaml:"tailscale"`
	Storage    Storage              `yaml:"storage"`
	Limits     Limits               `yaml:"limits"`
	Ecosystems map[string]Ecosystem `yaml:"ecosystems"`
}

type Tailscale struct {
	Hostname   string   `yaml:"hostname"`
	StateDir   string   `yaml:"state_dir"`
	Capability string   `yaml:"capability"`
	Tags       []string `yaml:"tags"`
}

type StoreConfig struct {
	Driver          string   `yaml:"driver"` // "fs" or "s3"
	Path            string   `yaml:"path"`
	Bucket          string   `yaml:"bucket"`
	Endpoint        string   `yaml:"endpoint"`
	Region          string   `yaml:"region"`
	Prefix          string   `yaml:"prefix"`
	AccessKeyID     string   `yaml:"access_key_id"`
	SecretAccessKey string   `yaml:"secret_access_key"`
	MaxSize         ByteSize `yaml:"max_size"`
}

type Storage struct {
	Cache  StoreConfig            `yaml:"cache"`
	State  StoreConfig            `yaml:"state"`
	Stores map[string]StoreConfig `yaml:"stores"`
}

type Limits struct {
	MaxUploadBytes           ByteSize `yaml:"max_upload_bytes"`
	MaxDecompressedBytes     ByteSize `yaml:"max_decompressed_bytes"`
	MaxArchiveEntries        int      `yaml:"max_archive_entries"`
	RequestsPerSecond        float64  `yaml:"requests_per_second"`
	Burst                    int      `yaml:"burst"`
	UpstreamFetchesPerSecond float64  `yaml:"upstream_fetches_per_second"`
}

type Ecosystem struct {
	Sources []Source `yaml:"sources"`
}

type Source struct {
	Name                string                `yaml:"name"`
	Type                string                `yaml:"type"` // "git", "storage" or "registry"
	Claims              []string              `yaml:"claims"`
	Remotes             []string              `yaml:"remotes"`
	Branches            []string              `yaml:"branches"`
	SSHKey              string                `yaml:"ssh_key"`
	KnownHosts          string                `yaml:"known_hosts"`
	Token               string                `yaml:"token"`
	Store               string                `yaml:"store"`
	URL                 string                `yaml:"url"`
	FetchHosts          []string              `yaml:"fetch_hosts"`
	Credentials         *Credential           `yaml:"credentials"`
	DownloadCredentials map[string]Credential `yaml:"download_credentials"`
	MetadataTTL         time.Duration         `yaml:"metadata_ttl"`
	PollInterval        time.Duration         `yaml:"poll_interval"`
}

type Credential struct {
	Bearer   string `yaml:"bearer"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ByteSize is a size in bytes. YAML accepts plain integers or an integer
// with a KiB, MiB, GiB or TiB suffix.
type ByteSize int64

var byteSizeRe = regexp.MustCompile(`^(\d+)\s*(KiB|MiB|GiB|TiB)?$`)

var byteUnits = map[string]int64{"": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	m := byteSizeRe.FindStringSubmatch(strings.TrimSpace(n.Value))
	if n.Kind != yaml.ScalarNode || m == nil {
		return fmt.Errorf("line %d: invalid byte size %q (use e.g. 100MiB, 50GiB or a plain integer)", n.Line, n.Value)
	}
	v, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || v > (1<<63-1)/byteUnits[m[2]] {
		return fmt.Errorf("line %d: invalid byte size %q: out of range", n.Line, n.Value)
	}
	*b = ByteSize(v * byteUnits[m[2]])
	return nil
}

// Load reads, decodes, expands secrets in, defaults and validates the file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := expand(reflect.ValueOf(&c).Elem()); err != nil {
		return nil, err
	}
	applyDefaults(&c)
	if err := Validate(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func applyDefaults(c *Config) {
	setStr(&c.Tailscale.Hostname, "registry")
	setStr(&c.Tailscale.Capability, "github.com/radiergummi/tspackages")
	l := &c.Limits
	setNum(&l.MaxUploadBytes, 100<<20)
	setNum(&l.MaxDecompressedBytes, 500<<20)
	setNum(&l.MaxArchiveEntries, 20000)
	setNum(&l.RequestsPerSecond, 50)
	setNum(&l.Burst, 100)
	setNum(&l.UpstreamFetchesPerSecond, 10)
	for eco, e := range c.Ecosystems {
		for i := range e.Sources {
			setNum(&e.Sources[i].MetadataTTL, 5*time.Minute)
			setNum(&e.Sources[i].PollInterval, time.Minute)
		}
		c.Ecosystems[eco] = e
	}
}

func setStr(p *string, def string) {
	if *p == "" {
		*p = def
	}
}

func setNum[T ~int | ~int64 | ~float64](p *T, def T) {
	if *p == 0 {
		*p = def
	}
}

var refRe = regexp.MustCompile(`\$\{(env|file):([^}]*)\}`)

// expand replaces ${env:NAME} and ${file:/path} in every string reachable
// from v, collecting all failures.
func expand(v reflect.Value) error {
	var errs []error
	switch v.Kind() {
	case reflect.String:
		s, err := expandString(v.String())
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Pointer:
		if !v.IsNil() {
			return expand(v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			errs = append(errs, expand(v.Field(i)))
		}
	case reflect.Slice:
		for i := range v.Len() {
			errs = append(errs, expand(v.Index(i)))
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			elem := reflect.New(v.Type().Elem()).Elem()
			elem.Set(v.MapIndex(k))
			errs = append(errs, expand(elem))
			v.SetMapIndex(k, elem)
		}
	}
	return errors.Join(errs...)
}

func expandString(s string) (string, error) {
	var errs []error
	out := refRe.ReplaceAllStringFunc(s, func(ref string) string {
		m := refRe.FindStringSubmatch(ref)
		if m[1] == "env" {
			val, ok := os.LookupEnv(m[2])
			if !ok {
				errs = append(errs, fmt.Errorf("environment variable %s is not set", m[2]))
			}
			return val
		}
		data, err := os.ReadFile(m[2])
		if err != nil {
			errs = append(errs, fmt.Errorf("read secret file: %w", err))
			return ""
		}
		return strings.TrimSuffix(string(data), "\n")
	})
	return out, errors.Join(errs...)
}
