// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// SysdigPath is the Sysdig Secure cloud-connector events ingest endpoint.
	// Payload is snake_case; backend silently drops events whose policy_id is unknown.
	SysdigPath string = "/api/v1/eventsDispatch/ingest"

	sysdigProductHeader      = "X-Sysdig-Product"
	sysdigProductHeaderValue = "SDS"
)

type sysdigEvent struct {
	UUID         string                 `json:"uuid,omitempty"`
	Timestamp    string                 `json:"timestamp"`
	Name         string                 `json:"name,omitempty"`
	Rule         string                 `json:"rule"`
	Priority     string                 `json:"priority"`
	Output       string                 `json:"output"`
	PolicyID     uint64                 `json:"policy_id,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	OutputFields map[string]interface{} `json:"output_fields,omitempty"`
}

type sysdigBatch struct {
	Time   string            `json:"time"`
	Labels map[string]string `json:"labels,omitempty"`
	Events []sysdigEvent     `json:"events"`
}

func newSysdigPayload(falcopayload types.FalcoPayload, config *types.Configuration) sysdigBatch {
	ts := falcopayload.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	tsStr := ts.UTC().Format(time.RFC3339Nano)

	return sysdigBatch{
		Time: tsStr,
		Events: []sysdigEvent{
			{
				UUID:         falcopayload.UUID,
				Timestamp:    tsStr,
				Name:         falcopayload.Rule,
				Rule:         falcopayload.Rule,
				Priority:     strings.ToLower(falcopayload.Priority.String()),
				Output:       falcopayload.Output,
				PolicyID:     config.Sysdig.PolicyID,
				Source:       falcopayload.Source,
				Tags:         falcopayload.Tags,
				OutputFields: falcopayload.OutputFields,
			},
		},
	}
}

// SysdigPost posts an event to Sysdig Secure via /api/v1/eventsDispatch/ingest.
func (c *Client) SysdigPost(falcopayload types.FalcoPayload) {
	c.Stats.Sysdig.Add(Total, 1)

	reqOpts := []RequestOptionFunc{
		func(req *http.Request) {
			req.Header.Set(AuthorizationHeaderKey, Bearer+" "+c.Config.Sysdig.APIToken)
			req.Header.Set(sysdigProductHeader, sysdigProductHeaderValue)
		},
	}

	err := c.Post(newSysdigPayload(falcopayload, c.Config), reqOpts...)
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:sysdig", "status:error"})
		c.Stats.Sysdig.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "sysdig", "status": Error}).Inc()
		c.OTLPMetrics.Outputs.With(attribute.String("destination", "sysdig"),
			attribute.String("status", Error)).Inc()
		utils.Log(utils.ErrorLvl, c.OutputType, err.Error())
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:sysdig", "status:ok"})
	c.Stats.Sysdig.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "sysdig", "status": OK}).Inc()
	c.OTLPMetrics.Outputs.With(attribute.String("destination", "sysdig"),
		attribute.String("status", OK)).Inc()
}
