package diagnostics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend"
	"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/stretchr/testify/require"

	"github.com/grafana/grafana/pkg/infra/httpclient/harcapture"
)

func TestBundler_Build(t *testing.T) {
	dir := t.TempDir()
	// A non-default filename verifies the bundler reads the exact configured path, not "grafana.log".
	logPath := filepath.Join(dir, "custom.log")
	require.NoError(t, os.WriteFile(logPath, []byte("line1\nline2\n"), 0o600))

	// No HAR captured (empty buffer, nil response) -> traffic.har omitted; server.log always present.
	blob, err := NewBundler(logPath).Build(nil, &harcapture.Buffer{}, json.RawMessage(`{"id":1}`), nil)
	require.NoError(t, err)

	files := readTarGz(t, blob)
	require.Contains(t, files, "server.log")
	require.Contains(t, files, "panel.json")
	require.NotContains(t, files, "traffic.har", "no HAR was captured")
	require.NotContains(t, files, "dashboard.json", "no dashboard JSON supplied")
	require.Contains(t, string(files["server.log"]), "line2")
	require.JSONEq(t, `{"id":1}`, string(files["panel.json"]))
}

func TestMergeHAR(t *testing.T) {
	d1 := []byte(`{"log":{"creator":{"name":"A","version":"1"},"entries":[{"n":1}]}}`)
	d2 := []byte(`{"log":{"entries":[{"n":2},{"n":3}]}}`)
	malformed := []byte(`not json`)

	out := mergeHAR([][]byte{d1, malformed, d2})
	require.NotNil(t, out)

	var env struct {
		Log struct {
			Version string            `json:"version"`
			Creator json.RawMessage   `json:"creator"`
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	require.NoError(t, json.Unmarshal(out, &env))
	require.Equal(t, "1.2", env.Log.Version)
	require.Len(t, env.Log.Entries, 3, "entries from all valid docs are concatenated; malformed skipped")
	require.JSONEq(t, `{"name":"A","version":"1"}`, string(env.Log.Creator), "first creator is kept")

	require.Nil(t, mergeHAR([][]byte{malformed}), "no parseable entries -> nil")
	require.Nil(t, mergeHAR(nil))
}

func TestCollectHAR_ExternalFramesAndNilFrame(t *testing.T) {
	withHAR := data.NewFrame("")
	withHAR.Meta = &data.FrameMeta{Custom: map[string]interface{}{"har": `{"log":{"entries":[{"n":1}]}}`}}

	resp := &backend.QueryDataResponse{
		Responses: backend.Responses{
			// A nil frame must not panic (regression guard), and the HAR frame must be collected.
			"__har__": backend.DataResponse{Frames: data.Frames{nil, withHAR}},
		},
	}

	out := collectHAR(resp, &harcapture.Buffer{})
	require.NotNil(t, out)

	var env struct {
		Log struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	require.NoError(t, json.Unmarshal(out, &env))
	require.Len(t, env.Log.Entries, 1)

	_, ok := resp.Responses["__har__"]
	require.False(t, ok, "__har__ synthetic response is consumed, not returned to the client")
}

func TestCollectHAR_Empty(t *testing.T) {
	require.Nil(t, collectHAR(nil, &harcapture.Buffer{}))
	require.Nil(t, collectHAR(&backend.QueryDataResponse{Responses: backend.Responses{}}, &harcapture.Buffer{}))
}

func TestCollectHAR_BufferOnly_returnedVerbatim(t *testing.T) {
	buf := &harcapture.Buffer{}
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	require.NoError(t, err)
	buf.AddEntry(req, nil, time.Now(), time.Millisecond)

	out := collectHAR(nil, buf)
	require.NotNil(t, out)

	// With no external frames, the buffer's own HAR document is returned as-is (no mergeHAR
	// re-marshal round-trip), so it must be byte-identical to Buffer.ToHAR().
	want, err := buf.ToHAR()
	require.NoError(t, err)
	require.Equal(t, want, out)

	var doc struct {
		Log struct {
			Entries []json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Log.Entries, 1)
}

func TestBuildTarGz(t *testing.T) {
	blob, err := buildTarGz(map[string][]byte{"b.txt": []byte("bbb"), "a.txt": []byte("aaa")})
	require.NoError(t, err)

	files := readTarGz(t, blob)
	require.Equal(t, "aaa", string(files["a.txt"]))
	require.Equal(t, "bbb", string(files["b.txt"]))
}

func TestBuildTarGz_deterministicOrder(t *testing.T) {
	blob, err := buildTarGz(map[string][]byte{"b.txt": []byte("b"), "a.txt": []byte("a"), "c.txt": []byte("c")})
	require.NoError(t, err)

	gz, err := gzip.NewReader(bytes.NewReader(blob))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		names = append(names, hdr.Name)
	}
	require.Equal(t, []string{"a.txt", "b.txt", "c.txt"}, names, "files written in sorted order")
}

func TestIndentJSON(t *testing.T) {
	require.Equal(t, "{\n  \"a\": 1\n}", string(indentJSON([]byte(`{"a":1}`))))
	require.Equal(t, "not json", string(indentJSON([]byte("not json"))), "falls back to raw bytes when unparseable")
}

func readTarGz(t *testing.T, data []byte) map[string][]byte {
	t.Helper()

	gz, err := gzip.NewReader(bytes.NewReader(data))
	require.NoError(t, err)

	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		out[hdr.Name] = b
	}
	return out
}
