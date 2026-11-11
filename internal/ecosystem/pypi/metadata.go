package pypi

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
)

// Metadata is the part of a distribution's core metadata (wheel METADATA,
// sdist PKG-INFO) that tspackages checks and serves.
type Metadata struct {
	MetadataVersion, Name, Version, RequiresPython string
	RequiresDist, Dynamic                          []string
}

// ParseMetadata reads core metadata: RFC 822 style headers, as Python's
// email.parser reads them, up to the first blank line.
func ParseMetadata(b []byte) (Metadata, error) {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(b))).ReadMIMEHeader()
	// Metadata without a body ends at EOF instead of a blank line.
	if err != nil && !errors.Is(err, io.EOF) {
		return Metadata{}, fmt.Errorf("invalid core metadata: %w", err)
	}
	m := Metadata{
		MetadataVersion: h.Get("Metadata-Version"),
		Name:            h.Get("Name"),
		Version:         h.Get("Version"),
		RequiresPython:  h.Get("Requires-Python"),
		RequiresDist:    h.Values("Requires-Dist"),
		Dynamic:         h.Values("Dynamic"),
	}
	if m.MetadataVersion == "" || m.Name == "" || m.Version == "" {
		return Metadata{}, errors.New("core metadata lacks Metadata-Version, Name or Version")
	}
	return m, nil
}
