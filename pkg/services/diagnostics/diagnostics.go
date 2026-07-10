// Package diagnostics assembles on-demand datasource diagnostic bundles: captured HTTP traffic
// (HAR), a tail of the server log, and the panel/dashboard JSON. The HTTP handler in pkg/api runs
// the queries with capture active and delegates bundle assembly here.
package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"

	"github.com/grafana/grafana/pkg/infra/httpclient/harcapture"
)

// logTailLines is the number of trailing server-log lines included in the bundle.
const logTailLines = 1000

// logTailMaxBytes caps how much of the log file tail is read into memory.
const logTailMaxBytes = 512 * 1024

// Bundler assembles diagnostic bundles. It reads the server log from logFilePath.
type Bundler struct {
	logFilePath string
}

// NewBundler returns a Bundler that reads the server log from logFilePath. Callers should pass the
// operator-configured log file (the resolved [log.file] file_name), not an assumed name, so the
// bundle captures the real log on instances that customized it.
func NewBundler(logFilePath string) *Bundler {
	return &Bundler{logFilePath: logFilePath}
}

// Build assembles a .tar.gz bundle from the query response, the captured HAR buffer, and the
// optional panel/dashboard JSON the client supplied. traffic.har is omitted when nothing was
// captured; server.log is always included (it degrades to an explanatory note when no log file
// exists, e.g. containerised deployments logging to stdout).
func (b *Bundler) Build(resp *backend.QueryDataResponse, harBuffer *harcapture.Buffer, panelJSON, dashboardJSON json.RawMessage) ([]byte, error) {
	files := map[string][]byte{}

	if har := collectHAR(resp, harBuffer); len(har) > 0 {
		files["traffic.har"] = har
	}

	files["server.log"] = b.serverLogTail()

	if len(panelJSON) > 0 {
		files["panel.json"] = indentJSON(panelJSON)
	}
	if len(dashboardJSON) > 0 {
		files["dashboard.json"] = indentJSON(dashboardJSON)
	}

	return buildTarGz(files)
}

// collectHAR returns the captured HTTP traffic as HAR 1.2 JSON. It merges the two possible
// sources: the in-process buffer (core plugins) and the __har__ response frame(s) returned by
// externalized GRPC plugins. Returns nil when nothing was captured.
func collectHAR(resp *backend.QueryDataResponse, harBuffer *harcapture.Buffer) []byte {
	var bufferDoc []byte
	if harBuffer.Len() > 0 {
		if b, err := harBuffer.ToHAR(); err == nil {
			bufferDoc = b
		}
	}

	// __har__ frames carry capture from externalized gRPC plugins (out-of-process).
	var frameDocs [][]byte
	if resp != nil {
		if harResp, ok := resp.Responses["__har__"]; ok {
			delete(resp.Responses, "__har__")
			// A plugin may split its capture across multiple frames; collect every frame's HAR
			// payload rather than only the first, so no entries are lost.
			for _, frame := range harResp.Frames {
				if frame == nil || frame.Meta == nil {
					continue
				}
				custom, ok := frame.Meta.Custom.(map[string]interface{})
				if !ok {
					continue
				}
				if harStr, ok := custom["har"].(string); ok && harStr != "" {
					frameDocs = append(frameDocs, []byte(harStr))
				}
			}
		}
	}

	// Common case: only the in-process buffer captured traffic (core plugins). Its ToHAR output is
	// already a complete HAR 1.2 document, so return it directly rather than re-parsing and
	// re-marshaling every captured request/response through mergeHAR.
	if len(frameDocs) == 0 {
		return bufferDoc
	}

	docs := frameDocs
	if bufferDoc != nil {
		docs = append([][]byte{bufferDoc}, frameDocs...)
	}
	return mergeHAR(docs)
}

// mergeHAR combines multiple HAR 1.2 documents into a single one by concatenating their
// log.entries. Documents that fail to parse are skipped. Returns nil when there are no entries.
func mergeHAR(docs [][]byte) []byte {
	type harEnvelope struct {
		Log struct {
			Creator json.RawMessage   `json:"creator"`
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}

	entries := make([]json.RawMessage, 0)
	var creator json.RawMessage
	for _, d := range docs {
		var env harEnvelope
		if err := json.Unmarshal(d, &env); err != nil {
			continue
		}
		entries = append(entries, env.Log.Entries...)
		if creator == nil && len(env.Log.Creator) > 0 {
			creator = env.Log.Creator
		}
	}
	if len(entries) == 0 {
		return nil
	}
	if creator == nil {
		creator = json.RawMessage(`{"name":"Grafana","version":"1.0"}`)
	}

	out := map[string]any{
		"log": map[string]any{
			"version": "1.2",
			"creator": creator,
			"entries": entries,
		},
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// serverLogTail returns the last logTailLines of the Grafana server log. In containerised
// deployments where Grafana logs to stdout and no log file exists, it returns an explanatory note
// instead of failing.
func (b *Bundler) serverLogTail() []byte {
	logPath := b.logFilePath

	f, err := os.Open(logPath) // nolint:gosec // path derived from server config, not user input
	if err != nil {
		return []byte(fmt.Sprintf("no server log file at %s\n(in containerised deployments Grafana logs to stdout; collect container logs instead)\nopen error: %v\n", logPath, err))
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return []byte(fmt.Sprintf("failed to stat server log %s: %v\n", logPath, err))
	}

	// Read at most logTailMaxBytes from the end. The file is being written concurrently, so use
	// the byte count actually returned by ReadAt (buf[:n]) -- if the file was rotated or truncated
	// between Stat and ReadAt, this avoids emitting trailing zero padding.
	readLen := stat.Size()
	var offset int64
	if readLen > logTailMaxBytes {
		offset = readLen - logTailMaxBytes
		readLen = logTailMaxBytes
	}
	buf := make([]byte, readLen)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return []byte(fmt.Sprintf("failed to read server log %s: %v\n", logPath, err))
	}
	buf = buf[:n]

	lines := bytes.Split(buf, []byte("\n"))
	if offset > 0 && len(lines) > 0 {
		// Drop the first (likely partial) line when we started mid-file.
		lines = lines[1:]
	}
	if len(lines) > logTailLines {
		lines = lines[len(lines)-logTailLines:]
	}
	return bytes.Join(lines, []byte("\n"))
}

// buildTarGz packs the named files into a gzipped tar archive. Files are written in deterministic
// (sorted) name order.
func buildTarGz(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	now := time.Now()
	for _, name := range names {
		data := files[name]
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o600,
			Size:    int64(len(data)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// indentJSON pretty-prints raw JSON for readability in the bundle, falling back to the raw bytes
// if it cannot be parsed.
func indentJSON(raw []byte) []byte {
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return raw
	}
	return out.Bytes()
}
