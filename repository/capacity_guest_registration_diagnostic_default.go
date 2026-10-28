//go:build !linux || !nativequalification

package repository

func guestRegistrationFailure(_ string, err error) error { return err }
func GuestRegistrationDiagnostic(error) string           { return "" }
