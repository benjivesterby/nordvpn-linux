package internal

import (
	"errors"
)

var (
	ErrDaemonConnectionRefused = errors.New(DaemonConnRefusedErrorMessage)
	ErrSocketAccessDenied      = errors.New("Permission denied accessing " + DaemonSocket)
	ErrSocketNotFound          = errors.New(DaemonSocket + " not found")
	ErrUnhandled               = errors.New(UnhandledMessage)
	ErrGateway                 = errors.New("can't find gateway")
	ErrStdin                   = errors.New("Stdin: missing argument")
	ErrServerIsUnavailable     = errors.New(ServerUnavailableErrorMessage)
	ErrTagDoesNotExist         = errors.New(TagNonexistentErrorMessage)
	ErrGroupDoesNotExist       = errors.New(GroupNonexistentErrorMessage)
	ErrDoubleGroup             = errors.New(DoubleGroupErrorMessage)
	// ErrAlreadyLoggedIn is returned on repeated logins
	ErrAlreadyLoggedIn = errors.New("you are already logged in")
	// ErrNotLoggedIn is returned when the caller is expected to be logged in
	// but is not
	ErrNotLoggedIn = errors.New("you are not logged in")
	// ErrAnalyticsConsentMissing is returned when user tries to login via tray
	// but settings analytics consent failed for some reason. This should not happen.
	ErrAnalyticsConsentMissing = errors.New("analytics consent is required before continuing")
	ErrVirtualServerSelected   = errors.New(SpecifiedServerIsVirtualLocation)
	ErrNoNetWhenLoggingIn      = errors.New("You’re offline.\nWe can’t run this action without an internet connection. Please check it and try again.")
)
