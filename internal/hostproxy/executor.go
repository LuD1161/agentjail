package hostproxy

import (
	"context"
	"time"
)

type Executor interface {
	Execute(context.Context, Target, string, time.Duration, int, func(int)) Result
}

func NewExecutor() Executor { return platformExecutor{} }
