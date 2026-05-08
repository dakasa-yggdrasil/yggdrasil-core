package saml

import (
	"database/sql"

	cjsaml "github.com/crewjam/saml"
)

// dbAssertionMaker is a thin shim over crewjam/saml's DefaultAssertionMaker.
// It exists as a customization point: future revisions will populate
// attribute statements from the collaborator's role/team/permission catalog
// per attribute_mapping. For Phase 1 we delegate to default behavior so the
// IdP boots cleanly; downstream config drives attribute names via the SP
// registry, not the assertion shape itself.
type dbAssertionMaker struct {
	db *sql.DB
}

// MakeAssertion delegates to crewjam/saml's default and is the documented
// integration point for adding custom attribute statements later. Keeping
// the receiver shape lets the IdP call into here once attribute mapping is
// wired (Task 38 OIDC claim equivalence).
func (m dbAssertionMaker) MakeAssertion(req *cjsaml.IdpAuthnRequest, session *cjsaml.Session) error {
	return cjsaml.DefaultAssertionMaker{}.MakeAssertion(req, session)
}
