package grant

import (
	"errors"
	"fmt"
)

var (
	ErrAdapterKind       = errors.New("grant resource adapter kind mismatch")
	ErrResourceWidened   = errors.New("grant resource canonicalization widened authority")
	ErrInvalidActivation = errors.New("invalid grant activation requirement")
)

type ActivationRequirement string

const (
	ActivationNotRequired ActivationRequirement = "not_required"
	ActivationRequired    ActivationRequirement = "required"
)

// ResourceAdapter owns matching semantics for one resource kind.
// See ADR 0141-runtime-grants.
type ResourceAdapter interface {
	Kind() ResourceKind
	Canonicalize(requested Resource) (Resource, error)
	Equivalent(left, right Resource) bool
	Covers(granted, requested Resource) bool
	ActivationFor(action Action, resource Resource) (ActivationRequirement, error)
}

// AdaptedResource is canonical authority plus its activation requirement.
type AdaptedResource struct {
	resource   Resource
	activation ActivationRequirement
}

func AdaptResource(
	adapter ResourceAdapter,
	action Action,
	requested Resource,
) (AdaptedResource, error) {
	if adapter == nil || !requested.Valid() || adapter.Kind() != requested.Kind() {
		return AdaptedResource{}, ErrAdapterKind
	}
	if !action.Valid() || !actionSupportsResource(action, requested.Kind()) {
		return AdaptedResource{}, ErrInvalidAction
	}

	canonical, err := adapter.Canonicalize(requested)
	if err != nil {
		return AdaptedResource{}, fmt.Errorf("canonicalize grant resource: %w", err)
	}
	if !canonical.Valid() || canonical.Kind() != requested.Kind() {
		return AdaptedResource{}, ErrAdapterKind
	}
	if !adapter.Equivalent(requested, canonical) ||
		!adapter.Covers(canonical, requested) ||
		!adapter.Covers(requested, canonical) {
		return AdaptedResource{}, ErrResourceWidened
	}

	activation, err := adapter.ActivationFor(action, canonical)
	if err != nil {
		return AdaptedResource{}, fmt.Errorf("grant resource activation: %w", err)
	}
	if !activation.Valid() {
		return AdaptedResource{}, ErrInvalidActivation
	}
	return AdaptedResource{resource: canonical, activation: activation}, nil
}

func (r AdaptedResource) Resource() Resource {
	return r.resource
}

func (r AdaptedResource) Activation() ActivationRequirement {
	return r.activation
}

func (r AdaptedResource) Valid() bool {
	return r.resource.Valid() && r.activation.Valid()
}

func (r ActivationRequirement) Valid() bool {
	return r == ActivationNotRequired || r == ActivationRequired
}
