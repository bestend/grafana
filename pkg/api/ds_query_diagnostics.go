package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/open-feature/go-sdk/openfeature"

	"github.com/grafana/grafana/pkg/api/dtos"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/httpclient/harcapture"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/diagnostics"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/web"
)

// diagnosticsRequest is the body posted by the "Download diagnostics" panel action. It carries
// the datasource queries to run with HAR capture active, plus the optional panel and dashboard
// definitions the client already holds (so we avoid a dashboard-service lookup).
type diagnosticsRequest struct {
	dtos.MetricRequest
	Dashboard json.RawMessage `json:"dashboard"`
	Panel     json.RawMessage `json:"panel"`
}

// diagnosticsFeatureClient is a shared OpenFeature client reused across requests (its evaluations
// resolve against the current global provider), so we don't allocate one per request.
var diagnosticsFeatureClient = openfeature.NewDefaultClient()

// QueryDiagnostics executes the supplied datasource queries with HAR capture active and returns a
// .tar.gz diagnostic bundle (captured traffic, a tail of the server log, and the panel/dashboard
// JSON). Bundle assembly lives in the diagnostics service; this handler owns the HTTP concerns:
// gating, request binding, running the queries, and writing the response.
//
// Two independent gates apply by design (see registerRoutes): the route is registered only on
// on-prem/self-managed instances (empty StackID) so it never runs on Grafana Cloud, and within
// on-prem it is gated at request time on the grafana.onDemandDiagnostics feature flag. Access is
// further restricted to Grafana server admins via reqGrafanaAdmin.
func (hs *HTTPServer) QueryDiagnostics(c *contextmodel.ReqContext) response.Response {
	ctx := c.Req.Context()
	if !diagnosticsFeatureClient.Boolean(ctx, featuremgmt.FlagGrafanaOnDemandDiagnostics, false, openfeature.TransactionContext(ctx)) {
		return response.Error(http.StatusNotFound, "on-demand diagnostics is not enabled", nil)
	}

	reqDTO := diagnosticsRequest{}
	if err := web.Bind(c.Req, &reqDTO); err != nil {
		return response.Error(http.StatusBadRequest, "bad request data", err)
	}
	if len(reqDTO.Queries) == 0 {
		return response.Error(http.StatusBadRequest, "at least one query is required", nil)
	}

	captureCtx, harBuffer := harcapture.WithCapture(ctx)
	c.Req = c.Req.WithContext(captureCtx)

	resp, err := hs.queryDataService.QueryData(captureCtx, c.SignedInUser, c.SkipDSCache, reqDTO.MetricRequest)
	if err != nil {
		return hs.handleQueryMetricsError(err)
	}

	// Resolve the operator-configured log file (mirrors log.ReadLoggingConfig) rather than assuming
	// grafana.log, so the bundle captures the real log on instances that set a custom file_name.
	logFilePath := hs.Cfg.Raw.Section("log.file").Key("file_name").MustString(filepath.Join(hs.Cfg.LogsPath, "grafana.log"))

	bundle, err := diagnostics.NewBundler(logFilePath).Build(resp, harBuffer, reqDTO.Panel, reqDTO.Dashboard)
	if err != nil {
		return response.Error(http.StatusInternalServerError, "failed to build diagnostics bundle", err)
	}

	filename := fmt.Sprintf("diagnostics-%s.tar.gz", time.Now().Format("20060102-150405"))
	header := http.Header{}
	header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	header.Set("Content-Type", "application/tar+gzip")
	return response.CreateNormalResponse(header, bundle, http.StatusOK)
}
