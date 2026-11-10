// Copyright (C) 2026 PPanel contributors <https://github.com/perfect-panel>
// SPDX-License-Identifier: GPL-3.0-or-later

package nowhere

import (
	"errors"
	"fmt"
)

// SetupError lets a sing connection handler choose the protocol result sent
// to a client when flow admission or outbound setup fails.
type SetupError struct {
	Result SetupResult
	Err    error
}

func (err *SetupError) Error() string {
	if err == nil {
		return "nowhere: flow setup failed"
	}
	if err.Err == nil {
		return fmt.Sprintf("nowhere: flow setup failed (%d)", err.Result)
	}
	return fmt.Sprintf("nowhere: flow setup failed (%d): %v", err.Result, err.Err)
}

func (err *SetupError) Unwrap() error { return err.Err }

// NewSetupError wraps an error with the wire result that should be returned to
// the Nowhere client.
func NewSetupError(result SetupResult, err error) error {
	if err == nil {
		return nil
	}
	return &SetupError{Result: result, Err: err}
}

// SetupResultFromError returns an explicit setup result or SetupDialFailed.
func SetupResultFromError(err error) SetupResult {
	var setupError *SetupError
	if errors.As(err, &setupError) && setupError != nil &&
		setupError.Result.Validate() == nil && setupError.Result != SetupReady {
		return setupError.Result
	}
	return SetupDialFailed
}
