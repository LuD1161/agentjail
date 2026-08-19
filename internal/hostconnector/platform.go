package hostconnector

import "context"

type unavailableBackend struct{}

func (unavailableBackend) Activate(context.Context, Activation) (Adapter, error) {
	return nil, ErrPlatformUnavailable
}
