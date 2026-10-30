package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestListCollaboratorsAllocationUsesNormalizedLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input int
		limit int
	}{
		{"negative", -1, model.DefaultPaginationLimit},
		{"zero", 0, model.DefaultPaginationLimit},
		{"small", 3, 3},
		{"maximum_integer", int(^uint(0) >> 1), model.MaxPaginationLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectQuery("FROM public.collaborators").WithArgs(tc.limit + 1).
				WillReturnRows(sqlmock.NewRows([]string{"id"}))
			got, _, err := ListCollaboratorsPaginated(context.Background(), db, model.ListCollaboratorsRequest{}, model.PaginationRequest{Limit: tc.input})
			if err != nil || got == nil || len(got) != 0 || cap(got) != tc.limit {
				t.Fatalf("normalized page allocation differs: len=%d cap=%d err=%v", len(got), cap(got), err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
