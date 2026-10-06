package probe

import (
	"context"
	"time"

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
	// Expire due leases before acquiring the write lock. The decisive lease
	// state is re-checked inside the transaction, so this cannot cause a race.
	if _, err := s.expirer.ExpireDue(ctx); err != nil {
		return domain.Probe{}, err
	}
	fingerprint := domain.ProbeFingerprint(leaseID, input)
	var result domain.Probe
	err := s.store.Write(ctx, func(state *domain.State) error {
		lease, ok := state.Leases[leaseID]
		if !ok {
			return domain.NotFound("lease", leaseID)
		}
		// A lease already bound to a probe is an idempotent replay: return the
		// recorded probe without any write. The decision is made against the
		// current state under the write lock, so a lease that a concurrent
		// release committed first is never reported over.
		if lease.State == domain.LeaseReported && lease.ProbeID != "" {
			existing, found := state.Probes[lease.ProbeID]
			if !found {
				return domain.NewError(domain.CodeStorageFailure, "lease references a missing probe", map[string]any{
					"probe_id": lease.ProbeID,
				})
			}
			if existing.PayloadFingerprint != fingerprint {
				return domain.NewError(domain.CodeIdempotencyConflict, "request key was reused with different probe content", map[string]any{
					"lease_id":    leaseID,
					"request_key": input.RequestKey,
				})
			}
			result = existing
			return store.ErrNoChange
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
		probe := domain.Probe{
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
		reportedLease, reportedNode := transition.ApplyProbe(probe.ID)
		state.Probes[probe.ID] = probe
		state.Leases[leaseID] = reportedLease
		state.Nodes[reportedNode.ID] = reportedNode
		store.AddAudit(state, s.ids, "probe", probe.ID, "stored", now, map[string]any{
			"lease_id": leaseID,
			"plan_id":  transition.Lease.PlanID,
		})
		result = probe
		return nil
	})
	return result, err
}

func pointer(value time.Time) *time.Time {
	return &value
}
