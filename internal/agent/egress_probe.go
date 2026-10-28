package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/OboardProject/oboard-agent/internal/model"
)

const (
	externalEgressProbeConcurrency  = 4
	externalEgressProbeTimeout      = 8 * time.Second
	externalEgressProbeBatchTimeout = 60 * time.Second
	externalEgressProbeTargetLimit  = 256
)

func (r *Runner) runExternalEgressProbeTask(ctx context.Context, plan model.ExternalEgressProbePlan) (model.ExternalEgressProbeResult, error) {
	if plan.Standalone != nil {
		return r.runStandaloneExternalProbe(ctx, plan)
	}
	result := model.ExternalEgressProbeResult{Items: make([]model.ExternalEgressProbeItem, len(plan.Targets))}
	if len(plan.Targets) == 0 {
		return result, errors.New("external egress probe has no targets")
	}
	if len(plan.Targets) > externalEgressProbeTargetLimit {
		return result, fmt.Errorf("external egress probe target count exceeds %d", externalEgressProbeTargetLimit)
	}
	if err := r.verifyExternalEgressConfigVersion(plan.ExpectedConfigVersion); err != nil {
		for i, target := range plan.Targets {
			result.Items[i] = model.ExternalEgressProbeItem{ProbeID: target.ProbeID, Status: "failed", Error: boundedExternalEgressProbeError(err.Error())}
		}
		return result, err
	}
	timeout := time.Duration(plan.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > externalEgressProbeTimeout {
		timeout = externalEgressProbeTimeout
	}
	batchCtx, cancel := context.WithTimeout(ctx, externalEgressProbeBatchTimeout)
	defer cancel()
	sem := make(chan struct{}, externalEgressProbeConcurrency)
	seen := map[string]bool{}
	var seenMu sync.Mutex
	var wg sync.WaitGroup
	for i, target := range plan.Targets {
		i, target := i, target
		result.Items[i] = model.ExternalEgressProbeItem{ProbeID: target.ProbeID, Status: "failed"}
		if target.ProbeID == "" || target.PathID <= 0 || target.ExternalOutboundID <= 0 || target.OwnerServerID <= 0 || strings.TrimSpace(target.OutboundTag) == "" || strings.TrimSpace(target.TopologyFingerprint) == "" {
			result.Items[i].Error = "invalid external egress probe target"
			continue
		}
		seenMu.Lock()
		duplicate := seen[target.ProbeID]
		seen[target.ProbeID] = true
		seenMu.Unlock()
		if duplicate {
			result.Items[i].Error = "duplicate external egress probe_id"
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				result.Items[i].Error = boundedExternalEgressProbeError(batchCtx.Err().Error())
				return
			}
			probeCtx, probeCancel := context.WithTimeout(batchCtx, timeout)
			defer probeCancel()
			exitIP, err := r.probeCoreOutboundEgressIP(probeCtx, target.OutboundTag)
			if err != nil {
				result.Items[i].Error = boundedExternalEgressProbeError(err.Error())
				return
			}
			result.Items[i].Status = "succeeded"
			result.Items[i].ExitIP = exitIP
		}()
	}
	wg.Wait()
	failed := 0
	for i := range result.Items {
		if result.Items[i].Status != "succeeded" {
			failed++
			if result.Items[i].Error == "" {
				result.Items[i].Error = "external egress probe failed"
			}
		}
	}
	if failed > 0 {
		return result, fmt.Errorf("%d external egress probe target(s) failed", failed)
	}
	return result, nil
}

func (r *Runner) verifyExternalEgressConfigVersion(expected int64) error {
	if expected <= 0 {
		return errors.New("expected_config_version must be positive")
	}
	state, err := r.loadAppliedVersion()
	if err != nil {
		return err
	}
	if state.Version != expected {
		return fmt.Errorf("expected config version %d, active version is %d", expected, state.Version)
	}
	return nil
}

func (r *Runner) probeCoreOutboundEgressIP(ctx context.Context, outboundTag string) (string, error) {
	body, err := json.Marshal(map[string]string{"outbound_tag": strings.TrimSpace(outboundTag)})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/outbounds/egress-ip", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		messageText := strings.TrimSpace(string(message))
		if messageText == "" {
			messageText = http.StatusText(res.StatusCode)
		}
		return "", fmt.Errorf("core egress probe status %d: %s", res.StatusCode, messageText)
	}
	var payload struct {
		ExitIP string `json:"exit_ip"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&payload); err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(payload.ExitIP))
	if err != nil {
		return "", errors.New("core returned an invalid egress IP")
	}
	return addr.Unmap().String(), nil
}

func boundedExternalEgressProbeError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func (r *Runner) runStandaloneExternalProbe(ctx context.Context, plan model.ExternalEgressProbePlan) (model.ExternalEgressProbeResult, error) {
	probe := plan.Standalone
	result := model.ExternalEgressProbeResult{}
	if probe == nil || probe.ExternalOutboundID <= 0 || len(probe.Fingerprint) != 64 || len(probe.Outbound) == 0 || len(probe.Outbound) > 65536 || len(plan.Targets) != 0 {
		return result, errors.New("invalid standalone probe")
	}
	item := model.ExternalEgressProbeItem{ProbeID: probe.Fingerprint, Status: "failed"}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://oboard-sb/outbounds/check", bytes.NewReader(probe.Outbound))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := r.coreClient
	if client == nil {
		client = unixHTTPClient(r.coreAPISocketPath())
	}
	response, err := client.Do(req)
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK {
			var body struct {
				ExitIP string `json:"exit_ip"`
			}
			err = json.NewDecoder(io.LimitReader(response.Body, 1024)).Decode(&body)
			if err == nil {
				addr, parseErr := netip.ParseAddr(body.ExitIP)
				if parseErr != nil {
					err = errors.New("invalid proxy exit IP")
				} else {
					item.Status, item.ExitIP = "succeeded", addr.Unmap().String()
				}
			}
		} else {
			err = errors.New("proxy authentication or exit request failed")
		}
	}
	if err != nil {
		item.Error = "代理连接或出口查询失败，请检查地址、凭证及 TLS 设置"
	}
	result.Items = []model.ExternalEgressProbeItem{item}
	return result, err
}
