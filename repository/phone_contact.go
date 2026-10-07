package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var (
	ErrPhoneRequired        = errors.New("phone_e164 is required for a new human collaborator")
	ErrPhoneUnavailable     = errors.New("phone contact is unavailable")
	ErrPhoneProfileRequired = errors.New("phone profile completion is required")
)

const phoneRequirementProjectionKey = "_yggdrasil_phone_profile_required"

type sealedPhone struct {
	CollaboratorID string `json:"collaborator_id"`
	PhoneE164      string `json:"phone_e164"`
}

// SetPhoneContactTx binds the encrypted payload to its canonical owner so a
// ciphertext/DEK swap across rows cannot silently change a recipient. Audit
// contains only identity and declaration state, never values or fingerprints.
func SetPhoneContactTx(ctx context.Context, tx *sql.Tx, envelope *cryptoenvelope.Envelope, id uuid.UUID, phone, actor, source string) (model.PhoneContact, error) {
	if err := contactphone.Validate(phone); err != nil {
		return model.PhoneContact{}, err
	}
	if envelope == nil || id == uuid.Nil || actor == "" || source != "self_profile" && source != "operator_assertion" {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	// Lock the collaborator first, matching the ordinary profile writer order.
	var present uuid.UUID
	if err := tx.QueryRowContext(ctx, `SELECT id FROM public.collaborators WHERE id=$1 FOR UPDATE`, id).Scan(&present); err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	plaintext, err := json.Marshal(sealedPhone{CollaboratorID: id.String(), PhoneE164: phone})
	if err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	ct, dek, err := envelope.Seal(ctx, plaintext)
	clear(plaintext)
	if err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	out := model.PhoneContact{CollaboratorID: id.String(), PhoneE164: phone, Assurance: "declared", DeclarationSource: source}
	err = tx.QueryRowContext(ctx, `
		INSERT INTO public.collaborator_phone_contacts
		(collaborator_id,phone_ciphertext,phone_dek,declaration_source,declared_by)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (collaborator_id) DO UPDATE SET
		phone_ciphertext=EXCLUDED.phone_ciphertext,phone_dek=EXCLUDED.phone_dek,
		declaration_source=EXCLUDED.declaration_source,declared_by=EXCLUDED.declared_by,
		declared_at=NOW(),version=collaborator_phone_contacts.version+1,updated_at=NOW()
		RETURNING declared_at,version`, id, ct, dek, source, actor).Scan(&out.DeclaredAt, &out.Version)
	if err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE public.collaborators SET phone_profile_required=FALSE,version=version+1 WHERE id=$1`, id); err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	// The database transaction also owns this audit record: declaration and
	// profile completion cannot commit without its non-personal trail.
	if _, err := tx.ExecContext(ctx, `INSERT INTO public.audit_events (actor,action,resource_kind,resource_id,outcome,metadata) VALUES ($1,'collaborator.phone_declared','collaborator',$2,'success',$3::jsonb)`, actor, id.String(), `{"assurance":"declared"}`); err != nil {
		return model.PhoneContact{}, ErrPhoneUnavailable
	}
	return out, nil
}

func GetPhoneContact(ctx context.Context, db dbtx, envelope *cryptoenvelope.Envelope, id uuid.UUID) (*model.PhoneContact, error) {
	if envelope == nil {
		return nil, ErrPhoneUnavailable
	}
	var ct, dek []byte
	out := model.PhoneContact{CollaboratorID: id.String(), Assurance: "declared"}
	err := db.QueryRowContext(ctx, `SELECT phone_ciphertext,phone_dek,declaration_source,declared_at,version FROM public.collaborator_phone_contacts WHERE collaborator_id=$1`, id).Scan(&ct, &dek, &out.DeclarationSource, &out.DeclaredAt, &out.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrPhoneUnavailable
	}
	out.PhoneE164, err = OpenPhoneContact(ctx, envelope, id.String(), ct, dek)
	if err != nil {
		return nil, ErrPhoneUnavailable
	}
	return &out, nil
}

func OpenPhoneContact(ctx context.Context, envelope *cryptoenvelope.Envelope, id string, ct, dek []byte) (string, error) {
	if envelope == nil {
		return "", ErrPhoneUnavailable
	}
	plaintext, err := envelope.Open(ctx, ct, dek)
	if err != nil {
		return "", ErrPhoneUnavailable
	}
	defer clear(plaintext)
	var payload sealedPhone
	if json.Unmarshal(plaintext, &payload) != nil || payload.CollaboratorID != id || contactphone.Validate(payload.PhoneE164) != nil {
		return "", ErrPhoneUnavailable
	}
	return payload.PhoneE164, nil
}

func initializePhoneEnrollmentTx(ctx context.Context, tx *sql.Tx, req model.CreateCollaboratorRequest, id uuid.UUID) error {
	required, err := contactphone.EnrollmentRequired()
	if err != nil {
		return err
	}
	if required {
		if _, err := tx.ExecContext(ctx, `UPDATE public.collaborators SET phone_profile_required=TRUE WHERE id=$1`, id); err != nil {
			return ErrPhoneUnavailable
		}
	}
	if req.PhoneE164 == "" {
		return nil
	}
	envelope, err := contactphone.EnvelopeFromEnv()
	if err != nil {
		return ErrPhoneUnavailable
	}
	actor := req.PhoneDeclaredBy
	if actor == "" {
		actor = "service:core-person-management"
	}
	_, err = SetPhoneContactTx(ctx, tx, envelope, id, req.PhoneE164, actor, "operator_assertion")
	return err
}

func validateNewPhone(req model.CreateCollaboratorRequest) error {
	required, err := contactphone.EnrollmentRequired()
	if err != nil {
		return err
	}
	if req.PhoneE164 != "" {
		return contactphone.Validate(req.PhoneE164)
	}
	if required && !req.ProvisionalPhone {
		return ErrPhoneRequired
	}
	return nil
}

func phoneRequirementAfterCreation(req model.CreateCollaboratorRequest) bool {
	required, _ := contactphone.EnrollmentRequired()
	return required && req.PhoneE164 == ""
}

// Token issuance rechecks the typed state without relying on a surface redirect
// or a token's old profile claims. A policy rollback does not clear this bit.
func RequirePhoneProfileComplete(ctx context.Context, db *sql.DB, id uuid.UUID) error {
	if db == nil || id == uuid.Nil {
		return ErrPhoneUnavailable
	}
	var pending bool
	if db.QueryRowContext(ctx, `SELECT phone_profile_required FROM public.collaborators WHERE id=$1`, id).Scan(&pending) != nil {
		return ErrPhoneUnavailable
	}
	if pending {
		return ErrPhoneProfileRequired
	}
	return nil
}

// Sensitive contact reads are opt-in exact grants. Existing wildcard/admin
// powers are deliberately not an implicit grant to this new PII projection.
func HasExactPhoneContactRead(ctx context.Context, db dbtx, id uuid.UUID) (bool, error) {
	var granted bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
		 SELECT 1 FROM public.team_grants tg
		 JOIN public.team_memberships tm ON tm.team_id=tg.team_id
		 JOIN public.teams t ON t.id=tm.team_id
		 JOIN public.collaborators c ON c.id=tm.collaborator_id AND c.status='active'
		 JOIN public.manifests mi ON mi.kind='integration_instance' AND mi.active
		  AND mi.namespace=tg.integration_instance_namespace AND mi.name=tg.integration_instance_name
		 JOIN public.manifests mt ON mt.kind='integration_type' AND mt.active
		  AND mt.name='yggdrasil-self'
		  AND ((mt.namespace=mi.spec->'type_ref'->>'namespace' AND mt.name=mi.spec->'type_ref'->>'name')
		    OR EXISTS(SELECT 1 FROM public.manifests ref
		      WHERE ref.id=NULLIF(mi.spec->'type_ref'->>'manifest_id','')::uuid
		      AND ref.kind='integration_type' AND ref.namespace=mt.namespace AND ref.name=mt.name))
		 WHERE tm.collaborator_id=$1 AND tg.action_name='yggdrasil:view_contact_phones'
		 AND `+authorizationMembershipPredicate+`
		)`, id).Scan(&granted)
	if err != nil {
		return false, ErrPhoneUnavailable
	}
	return granted, nil
}
