package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func (s *Server) serveGuestOriginalAuthorityV2(w http.ResponseWriter, r *http.Request, p *capacityGuestPrincipal, store repository.CapacityStore) {
	id := r.URL.Query().Get("request_id")
	phase := r.URL.Query().Get("phase")
	hash := r.Header.Values("X-Guest-Retirement-Intent-SHA256")
	parsed, err := uuid.Parse(id)
	if p == nil || r.Method != http.MethodGet || r.URL.Path != model.GuestRetirementV2AuthorityPath || r.URL.RawPath != "" || err != nil || parsed == uuid.Nil || parsed.String() != id || (phase != "before_start" && phase != "before_poweroff") || r.URL.RawQuery != "request_id="+id+"&phase="+phase || len(hash) != 1 || !capacity.ValidDigest(hash[0]) || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	original, err := store.GuestRetirementOriginalV2(r.Context(), p.base.principalID, id, hash[0])
	if err != nil || !guestScopeMatches(p, original.Binding, original.Member) {
		guestHTTPError(w, repository.ErrCapacityMutationAuthorization)
		return
	}
	read, err := store.ReserveGuestAuthorityReadV2(r.Context(), p.base.principalID, id, hash[0], phase)
	if err != nil {
		guestHTTPError(w, err)
		return
	}

	ctx, cancel := context.WithDeadline(r.Context(), read.Deadline)
	defer cancel()
	var observation *model.CapacityGuestRetirementObservationV2
	if phase == "before_poweroff" || read.Ordinal > 1 {
		client, err := guestPrivateHTTPClient(ctx, s.db, read.Original.Member)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		defer client.Close()
		body, err := json.Marshal(read.Original.Request)
		if err != nil {
			guestHTTPError(w, err)
			return
		}
		returned, callErr := client.Original(ctx, http.MethodGet, model.GuestRetirementV2ObservationPath, body)
		retention, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		recordErr := store.RecordGuestAuthorityTransportV2(retention, read, returned)
		stop()
		var actual model.CapacityGuestRetirementObservationV2
		if recordErr != nil || callErr != nil || capacity.GuestOriginalHTTPDecode(returned, &actual) != nil || store.RecordGuestObservationV2(ctx, id, actual) != nil {
			guestHTTPError(w, repository.ErrCapacityConflict)
			return
		}
		observation = &actual
	}
	authority, err := store.FinishGuestAuthorityReadV2(ctx, read, observation)
	if err != nil {
		guestHTTPError(w, err)
		return
	}
	guestCanonicalReply(w, authority)
}
