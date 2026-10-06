package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"
)

func ActivatePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanDraft {
		return InvalidState("plan can be activated only from draft", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	if plan.LatestRevisionID == "" {
		return InvalidState("plan needs a zone revision before activation", map[string]any{
			"plan_id": plan.ID,
		})
	}
	plan.State = PlanActive
	plan.ActivatedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

func CompletePlan(plan *RolloutPlan, now time.Time) error {
	if plan.State != PlanActive {
		return InvalidState("plan can be completed only from active", map[string]any{
			"plan_id": plan.ID,
			"state":   plan.State,
		})
	}
	plan.State = PlanCompleted
	plan.CompletedAt = timePointer(now.UTC())
	plan.Version++
	return nil
}

type LeaseTransitionKind string

const (
	LeaseTransitionRelease LeaseTransitionKind = "release"
	LeaseTransitionProbe   LeaseTransitionKind = "probe"
)

type LeaseTransition struct {
	Kind  LeaseTransitionKind
	Lease NodeLease
	Node  ResolverNode
	At    time.Time
}

func NewLeaseTransition(
	kind LeaseTransitionKind,
	lease NodeLease,
	node ResolverNode,
	at time.Time,
) LeaseTransition {
	copiedLease := lease
	if lease.FinishedAt != nil {
		finishedAt := *lease.FinishedAt
		copiedLease.FinishedAt = &finishedAt
	}
	return LeaseTransition{
		Kind:  kind,
		Lease: copiedLease,
		Node:  node,
		At:    at.UTC(),
	}
}

func (t LeaseTransition) Validate(now time.Time) error {
	if t.Kind != LeaseTransitionRelease && t.Kind != LeaseTransitionProbe {
		return NewError(CodeInternal, "lease transition kind is invalid", map[string]any{
			"kind": t.Kind,
		})
	}
	if t.Lease.ID == "" || t.Lease.NodeID == "" || t.Node.ID != t.Lease.NodeID {
		return NewError(CodeStorageFailure, "lease transition references inconsistent entities", map[string]any{
			"lease_id": t.Lease.ID,
			"node_id":  t.Lease.NodeID,
		})
	}
	if t.Lease.State != LeaseClaimed {
		return NewError(CodeLeaseNotClaimed, "lease is not claimed", map[string]any{
			"lease_id": t.Lease.ID,
			"state":    t.Lease.State,
		})
	}
	if t.Kind == LeaseTransitionProbe && !now.Before(t.Lease.ExpiresAt) {
		return NewError(CodeLeaseExpired, "lease has expired", map[string]any{
			"lease_id":   t.Lease.ID,
			"expires_at": t.Lease.ExpiresAt,
		})
	}
	return nil
}

func (t LeaseTransition) ApplyRelease() (NodeLease, ResolverNode) {
	lease := t.Lease
	finishedAt := t.At
	lease.State = LeaseReleased
	lease.FinishedAt = &finishedAt
	lease.ProbeID = ""
	node := t.Node
	if node.State == NodeLeased {
		node.State = NodeReady
		node.Version++
		node.UpdatedAt = t.At
	}
	return lease, node
}

func (t LeaseTransition) ApplyProbe(probeID string) (NodeLease, ResolverNode) {
	lease := t.Lease
	finishedAt := t.At
	lease.State = LeaseReported
	lease.FinishedAt = &finishedAt
	lease.ProbeID = probeID
	node := t.Node
	if node.State == NodeLeased {
		node.State = NodeReady
		node.Version++
		node.UpdatedAt = t.At
	}
	return lease, node
}

func LeaseFingerprint(planID string, input LeaseInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%d|%d",
		planID,
		input.RequestKey,
		input.Region,
		input.LeaseSeconds,
		input.MaxNodes,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func ProbeFingerprint(leaseID string, input ProbeInput) string {
	payload := fmt.Sprintf(
		"%s|%s|%t|%d|%d|%s",
		leaseID,
		input.RequestKey,
		input.Success,
		input.ObservedSerial,
		input.LatencyMS,
		input.ObservedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func BuildAssessment(
	id string,
	plan RolloutPlan,
	revision ZoneRevision,
	probes []Probe,
	now time.Time,
) RolloutAssessment {
	reasons := make(map[string]struct{})
	if len(probes) == 0 {
		reasons["no_probes"] = struct{}{}
	}
	probeCount := len(probes)
	successCount := 0
	maximumLatency := 0
	nodes := make(map[string]struct{})
	for _, probe := range probes {
		nodes[probe.NodeID] = struct{}{}
		if probe.LatencyMS > maximumLatency {
			maximumLatency = probe.LatencyMS
		}
		if probe.Success {
			successCount++
			if probe.ObservedSerial != revision.Serial {
				reasons["serial_mismatch"] = struct{}{}
			}
		}
	}
	if len(nodes) < plan.ExpectedNodes {
		reasons["node_not_observed"] = struct{}{}
	}
	successRatio := 0.0
	if probeCount > 0 {
		successRatio = round(float64(successCount)/float64(probeCount), 6)
	}
	if successRatio < plan.MinimumSuccessRatio {
		reasons["success_ratio_below_minimum"] = struct{}{}
	}
	if maximumLatency > plan.MaximumLatencyMS {
		reasons["latency_limit_exceeded"] = struct{}{}
	}
	reasonList := make([]string, 0, len(reasons))
	for reason := range reasons {
		reasonList = append(reasonList, reason)
	}
	sort.Strings(reasonList)
	verdict := VerdictConsistent
	if len(reasonList) > 0 {
		verdict = VerdictReviewRequired
	}
	return RolloutAssessment{
		ID:               id,
		PlanID:           plan.ID,
		RevisionID:       revision.ID,
		Verdict:          verdict,
		Reasons:          reasonList,
		ProbeCount:       probeCount,
		SuccessCount:     successCount,
		SuccessRatio:     successRatio,
		MaximumLatencyMS: maximumLatency,
		CreatedAt:        now.UTC(),
	}
}

func round(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func timePointer(value time.Time) *time.Time {
	return &value
}
