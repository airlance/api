package bootstrap

import (
	"airlance.org/api/internal/data/repository/postgres"
	"airlance.org/api/internal/data/repository/redis"
	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/user"
	"airlance.org/api/internal/domain/wsticket"
)

type Repositories struct {
	User          user.Repository
	Identity      identity.Repository
	Session       session.Repository
	PasskeyCred   passkey.CredentialRepo
	Challenge     passkey.ChallengeRepo
	Device        device.Repository
	Audit         audit.Repository
	APIClient     apiclient.Repository
	RateLimitTier apiclient.TierRepository
	WSTicket      wsticket.Repository
	OTP           otp.Repository
}

func InitRepositories(infra *Infrastructures) *Repositories {
	return &Repositories{
		User:          postgres.NewUserRepository(infra.DBPool),
		Identity:      postgres.NewIdentityRepository(infra.DBPool),
		Session:       postgres.NewSessionRepository(infra.DBPool),
		PasskeyCred:   postgres.NewPasskeyCredentialRepository(infra.DBPool),
		Challenge:     postgres.NewChallengeRepository(infra.DBPool),
		Device:        postgres.NewDeviceRepository(infra.DBPool),
		Audit:         postgres.NewAuditRepository(infra.DBPool),
		APIClient:     postgres.NewAPIClientRepository(infra.DBPool),
		RateLimitTier: postgres.NewRateLimitTierRepository(infra.DBPool),
		WSTicket:      redis.NewWSTicketRepository(infra.RedisClient),
		OTP:           postgres.NewOTPRepository(infra.DBPool),
	}
}
