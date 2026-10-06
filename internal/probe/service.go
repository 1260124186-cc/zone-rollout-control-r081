package probe

import (
	"context"

	"solo-0014-zone-rollout-control/internal/domain"
	"solo-0014-zone-rollout-control/internal/platform"
	"solo-0014-zone-rollout-control/internal/store"
)

type LeaseExpirer interface {
	ExpireDue(context.Context) (int, error)
}

type Service struct {
	store   *store.Store
	clock   platform.Clock
	ids     platform.IDGenerator
	expirer LeaseExpirer
}

func New(
	stateStore *store.Store,
	clock platform.Clock,
	ids platform.IDGenerator,
	expirer LeaseExpirer,
) *Service {
	return &Service{store: stateStore, clock: clock, ids: ids, expirer: expirer}
}

func (s *Service) Submit(
	ctx context.Context,
	leaseID string,
	input domain.ProbeInput,
) (domain.Probe, error) {
	now := s.clock.Now().UTC()
	if err := domain.ValidateProbeInput(input, now); err != nil {
		return domain.Probe{}, err
	}
	if _, err := s.expirer.ExpireDue(ctx); err != nil {
		return domain.Probe{}, err
	}
	fingerprint := domain.ProbeFingerprint(leaseID, input)
	var result domain.Probe
	replay := false
	// Fast path: an already reported lease replays the stored probe (or
	// rejects a conflicting payload) without rewriting the snapshot.
	err := s.store.Read(ctx, func(state *domain.State) error {
		lease, ok := state.Leases[leaseID]
		if !ok {
			return domain.NotFound("lease", leaseID)
		}
		if lease.State != domain.LeaseReported || lease.ProbeID == "" {
			return nil
		}
		existing, err := replayableProbe(state, lease, leaseID, input.RequestKey, fingerprint)
		if err != nil {
			return err
		}
		result = existing
		replay = true
		return nil
	})
	if err != nil {
		return domain.Probe{}, err
	}
	if replay {
		return result, nil
	}
	// Re-validate and store inside a single write transaction so a
	// concurrent release on the same lease is either persisted first (and
	// this submission fails without leaving a probe behind) or sees the
	// reported state (and fails itself); the two outcomes can never both
	// be applied.
	err = s.store.Write(ctx, func(state *domain.State) error {
		lease, ok := state.Leases[leaseID]
		if !ok {
			return domain.NotFound("lease", leaseID)
		}
		if lease.State == domain.LeaseReported && lease.ProbeID != "" {
			// A concurrent submission was confirmed first; replay it.
			existing, err := replayableProbe(state, lease, leaseID, input.RequestKey, fingerprint)
			if err != nil {
				return err
			}
			result = existing
			return nil
		}
		if lease.State != domain.LeaseClaimed {
			return domain.NewError(domain.CodeLeaseNotClaimed, "lease is not claimed", map[string]any{
				"lease_id": leaseID,
				"state":    lease.State,
			})
		}
		plan, ok := state.Plans[lease.PlanID]
		if !ok {
			return domain.NewError(domain.CodeStorageFailure, "lease references a missing plan", map[string]any{
				"plan_id": lease.PlanID,
			})
		}
		if plan.State != domain.PlanActive {
			return domain.InvalidState("plan must be active to store probes", map[string]any{
				"plan_id": plan.ID,
				"state":   plan.State,
			})
		}
		node, ok := state.Nodes[lease.NodeID]
		if !ok {
			return domain.NewError(domain.CodeStorageFailure, "lease references a missing node", map[string]any{
				"node_id": lease.NodeID,
			})
		}
		transition := domain.NewLeaseTransition(
			domain.LeaseTransitionProbe,
			lease,
			node,
			now,
		)
		if err := transition.Validate(now); err != nil {
			return err
		}
		result = domain.Probe{
			ID:                 s.ids.New("prb"),
			LeaseID:            transition.Lease.ID,
			PlanID:             transition.Lease.PlanID,
			NodeID:             transition.Lease.NodeID,
			RequestKey:         input.RequestKey,
			Success:            input.Success,
			ObservedSerial:     input.ObservedSerial,
			LatencyMS:          input.LatencyMS,
			ObservedAt:         input.ObservedAt.UTC(),
			StoredAt:           now,
			PayloadFingerprint: fingerprint,
		}
		updatedLease, updatedNode := transition.ApplyProbe(result.ID)
		state.Probes[result.ID] = result
		state.Leases[leaseID] = updatedLease
		state.Nodes[updatedNode.ID] = updatedNode
		store.AddAudit(state, s.ids, "probe", result.ID, "stored", now, map[string]any{
			"lease_id": leaseID,
			"plan_id":  transition.Lease.PlanID,
		})
		return nil
	})
	return result, err
}

func replayableProbe(
	state *domain.State,
	lease domain.NodeLease,
	leaseID string,
	requestKey string,
	fingerprint string,
) (domain.Probe, error) {
	existing, found := state.Probes[lease.ProbeID]
	if !found {
		return domain.Probe{}, domain.NewError(domain.CodeStorageFailure, "lease references a missing probe", map[string]any{
			"probe_id": lease.ProbeID,
		})
	}
	if existing.PayloadFingerprint != fingerprint {
		return domain.Probe{}, domain.NewError(domain.CodeIdempotencyConflict, "request key was reused with different probe content", map[string]any{
			"lease_id":    leaseID,
			"request_key": requestKey,
		})
	}
	return existing, nil
}
