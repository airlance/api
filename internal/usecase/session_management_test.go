package usecase_test

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/infrastructure/memory"
	"github.com/airlance/api/internal/usecase"
)

func TestSessionManagementUseCase_LogoutAndTTL(t *testing.T) {
	accRepo := newMockAccountRepo()
	sessRepo := memory.NewSessionRepository()
	smUC := usecase.NewSessionManagementUseCase(sessRepo, accRepo)
	ctx := context.Background()

	acc, _ := accRepo.CreateAccount(ctx, "user@test.com", "Test", "User")
	sess1, _ := sessRepo.CreateSession(ctx, 1, acc.ID)
	sess2, _ := sessRepo.CreateSession(ctx, 2, acc.ID)

	active, err := smUC.ListSessions(ctx, acc.ID)
	if err != nil || len(active) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(active))
	}

	if err := smUC.Logout(ctx, sess1.ID); err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	activeAfter, _ := smUC.ListSessions(ctx, acc.ID)
	if len(activeAfter) != 1 || activeAfter[0].ID != sess2.ID {
		t.Fatalf("expected only sess2 remaining, got %v", activeAfter)
	}

	if err := smUC.SetSessionTTL(ctx, acc.ID, intPtr(5)); err != account.ErrInvalidSessionTTL {
		t.Fatalf("expected ErrInvalidSessionTTL for 5 months, got %v", err)
	}

	if err := smUC.SetSessionTTL(ctx, acc.ID, intPtr(6)); err != nil {
		t.Fatalf("expected success for 6 months, got %v", err)
	}

	updatedAcc, _ := accRepo.FindByID(ctx, acc.ID)
	if updatedAcc.SessionTTLMonths == nil || *updatedAcc.SessionTTLMonths != 6 {
		t.Fatalf("expected SessionTTLMonths=6, got %v", updatedAcc.SessionTTLMonths)
	}
}

func intPtr(v int) *int {
	return &v
}
