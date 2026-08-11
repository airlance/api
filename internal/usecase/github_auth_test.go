package usecase_test

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/oauth"
	"github.com/airlance/api/internal/infrastructure/memory"
	"github.com/airlance/api/internal/usecase"
)

type mockGithubClient struct {
	user oauth.GithubUser
}

func (m *mockGithubClient) AuthCodeURL(state string) string {
	return "https://github.com/login/oauth/authorize?state=" + state
}

func (m *mockGithubClient) Exchange(ctx context.Context, code string) (oauth.GithubUser, error) {
	return m.user, nil
}

func TestGithubAuthUseCase_AutoLinking(t *testing.T) {
	accRepo := newMockAccountRepo()
	idRepo := newMockIdentityRepo()
	devRepo := newMockDeviceRepo()
	sessRepo := memory.NewSessionRepository()

	existingAcc, err := accRepo.CreateAccount(context.Background(), "alice@example.com", "Alice", "Smith")
	if err != nil {
		t.Fatalf("CreateAccount failed: %v", err)
	}
	_ = accRepo.ConfirmAccount(context.Background(), existingAcc.ID)

	ghClient := &mockGithubClient{
		user: oauth.GithubUser{
			ID:            999888,
			Login:         "alicesmith",
			Email:         "alice@example.com",
			EmailVerified: true,
		},
	}

	githubAuth := usecase.NewGithubAuthUseCase(accRepo, idRepo, devRepo, sessRepo, ghClient, nil)
	ctx := context.Background()

	sess, err := githubAuth.CompleteAuth(ctx, "github_code_123", usecase.DeviceInfo{
		Fingerprint: "macbook_fp",
		DeviceName:  "MacBook Pro",
		Platform:    "macos",
	})
	if err != nil {
		t.Fatalf("CompleteAuth failed: %v", err)
	}

	if sess.AccountID != existingAcc.ID {
		t.Fatalf("expected auto-linking to account %d, got %d", existingAcc.ID, sess.AccountID)
	}

	id, err := idRepo.FindByProviderUserID(ctx, authidentity.ProviderGithub, "999888")
	if err != nil {
		t.Fatalf("Github identity not found: %v", err)
	}
	if id.AccountID != existingAcc.ID {
		t.Fatalf("expected identity linked to %d, got %d", existingAcc.ID, id.AccountID)
	}
}
