package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/domain/updatelog"
	emailinfra "github.com/airlance/api/internal/infrastructure/email"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/airlance/api/internal/infrastructure/nodeid"
	oauthinfra "github.com/airlance/api/internal/infrastructure/oauth"
	"github.com/airlance/api/internal/infrastructure/postgres"
	redisinfra "github.com/airlance/api/internal/infrastructure/redis"
	"github.com/airlance/api/internal/infrastructure/redisclient"
	"github.com/airlance/api/internal/infrastructure/serverkey"
	"github.com/airlance/api/internal/infrastructure/sessioncleanup"
	"github.com/airlance/api/internal/noiseik"
	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	"github.com/airlance/api/internal/transport"
	httpinfra "github.com/airlance/api/internal/transport/http"
	"github.com/airlance/api/internal/usecase"
	flatbuffers "github.com/google/flatbuffers/go"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	serveAddr             string
	serveKeyPath          string
	serveHeartbeatTimeout time.Duration
)

var serveCmd = &cobra.Command{
	Use:     "serve",
	Aliases: []string{"server"},
	Short:   "Start TCP + Noise IK messenger server",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("server: failed to load config: %w", err)
		}

		if err := logger.Init(cfg); err != nil {
			return fmt.Errorf("server: failed to init logger: %w", err)
		}

		if cmd.Flags().Changed("addr") {
			cfg.Server.Addr = serveAddr
		}
		if cmd.Flags().Changed("key") {
			cfg.Server.KeyPath = serveKeyPath
		}
		if cmd.Flags().Changed("heartbeat-timeout") {
			cfg.Server.HeartbeatTimeout = serveHeartbeatTimeout
		}

		nodeID, err := nodeid.Load(cfg.NodeID.Path)
		if err != nil {
			return fmt.Errorf("server: failed to load node_id: %w", err)
		}
		logger.Log.WithField("node_id", nodeID).Info("initialized node identity")

		kp, err := serverkey.LoadServerKeyPair(cfg.Server.KeyPath)
		if err != nil {
			return fmt.Errorf("server: failed to load server key from %s: %w", cfg.Server.KeyPath, err)
		}
		logger.Log.WithFields(logrus.Fields{
			"key_id":     kp.KeyID,
			"public_key": fmt.Sprintf("%x", kp.PublicKey().Bytes()),
		}).Info("loaded server keypair")

		db, err := sql.Open("postgres", cfg.Database.DSN)
		if err != nil {
			return fmt.Errorf("server: open db failed: %w", err)
		}
		defer db.Close()
		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("server: ping db failed: %w", err)
		}

		var redisClient *redisclient.Client
		if cfg.Redis.Addr != "" {
			var err error
			redisClient, err = redisclient.New(cfg.Redis)
			if err != nil {
				logger.Log.WithField("error", err).Warn("failed to connect to redis, proceeding with limited functionality")
			} else {
				defer redisClient.Close()
				logger.Log.WithField("addr", cfg.Redis.Addr).Info("connected to redis")
			}
		}

		uow := postgres.NewUnitOfWork(db)
		updateRepo := postgres.NewUpdateLogRepository(db)

		accountRepo := postgres.NewAccountRepository(db)
		authIdentityRepo := postgres.NewAuthIdentityRepository(db)
		deviceRepo := postgres.NewDeviceRepository(db)
		sessionRepo := postgres.NewSessionRepository(db)
		codeRepo := postgres.NewConfirmationCodeRepository(db)

		smtpClient := emailinfra.NewSMTPClient(cfg.SMTP)
		newDeviceNotifier := emailinfra.NewSMTPNewDeviceNotifier(smtpClient)
		logEmailSender := emailinfra.NewLogEmailSender()

		var qrloginRepo qrlogin.Repository
		var qrloginPubSub qrlogin.EventPublisher
		if redisClient != nil {
			qrloginRepo = redisinfra.NewQRLoginRepository(redisClient)
			qrloginPubSub = redisinfra.NewEventPublisher(redisClient)
		}

		githubClient := oauthinfra.NewGithubClient(cfg.Github)

		emailAuthUC := usecase.NewEmailAuthUseCase(accountRepo, authIdentityRepo, deviceRepo, sessionRepo, codeRepo, logEmailSender, newDeviceNotifier)
		githubAuthUC := usecase.NewGithubAuthUseCase(accountRepo, authIdentityRepo, deviceRepo, sessionRepo, githubClient, newDeviceNotifier)
		qrLoginUC := usecase.NewQRLoginUseCase(qrloginRepo, deviceRepo, sessionRepo, accountRepo, qrloginPubSub, newDeviceNotifier)
		sessionMgmtUC := usecase.NewSessionManagementUseCase(sessionRepo, accountRepo)

		sessionUC := usecase.NewSessionUseCase(sessionRepo, deviceRepo)
		heartbeatUC := usecase.NewHeartbeatUseCase(deviceRepo, sessionRepo)
		messageUC := usecase.NewMessageUseCase(uow, updateRepo, transport.NewConnectionRegistry()) // placeholder registry

		registry := transport.NewConnectionRegistry()
		messageUC = usecase.NewMessageUseCase(uow, updateRepo, registry)

		router := transport.NewMessageRouter()
		defer router.Close()

		httpServer := httpinfra.NewServer(cfg, githubAuthUC)
		go func() {
			logger.Log.WithField("addr", cfg.HTTP.Addr).Info("starting HTTP OAuth server")
			if err := httpServer.Start(); err != nil {
				logger.Log.WithField("error", err).Error("HTTP OAuth server stopped unexpectedly")
			}
		}()

		cleanupWorker := sessioncleanup.NewWorker(sessionRepo, 1*time.Hour)
		go cleanupWorker.Run(ctx)

		if redisClient != nil {
			startQRSubSubscriber(ctx, redisClient, nodeID, registry, qrLoginUC, updateRepo)
		}

		l := transport.NewListener(cfg.Server.Addr, newHandler(
			kp, nodeID, registry, router, accountRepo,
			emailAuthUC, githubAuthUC, qrLoginUC, sessionMgmtUC,
			sessionUC, heartbeatUC, messageUC, updateRepo, cfg.Server.HeartbeatTimeout,
		))
		logger.Log.WithFields(logrus.Fields{
			"addr":              cfg.Server.Addr,
			"heartbeat_timeout": cfg.Server.HeartbeatTimeout,
		}).Info("server starting TCP listener")

		return l.ListenAndServe()
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", ":8080", "TCP listen address")
	serveCmd.Flags().StringVar(&serveKeyPath, "key", "server-key.json", "path to server static keypair")
	serveCmd.Flags().DurationVar(&serveHeartbeatTimeout, "heartbeat-timeout", 60*time.Second, "read deadline timeout for idle client connections (e.g. 60s)")
}

func startQRSubSubscriber(ctx context.Context, rdb *redisclient.Client, nodeID string, registry *transport.ConnectionRegistry, qrLoginUC *usecase.QRLoginUseCase, updateRepo updatelog.Repository) {
	pubsub := rdb.Subscribe(ctx, redisinfra.EventChannel(nodeID))
	ch := pubsub.Channel()

	go func() {
		defer pubsub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				var ev qrlogin.Event
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
					continue
				}

				activeConn, ok := registry.GetPendingQR(ev.TicketID)
				if !ok || activeConn.Conn == nil {
					continue
				}

				noiseConn, ok := activeConn.Conn.(*noiseik.Conn)
				if !ok {
					continue
				}

				switch ev.Type {
				case qrlogin.EventScanned:
					_ = writeQRTicketStatusUpdate(noiseConn, 0, string(ev.TicketID), gen.QRTicketStatusSCANNED)
				case qrlogin.EventDenied:
					_ = writeQRTicketStatusUpdate(noiseConn, 0, string(ev.TicketID), gen.QRTicketStatusDENIED)
					registry.UnregisterPendingQR(ev.TicketID)
				case qrlogin.EventConfirmed:
					sess, err := qrLoginUC.Complete(ctx, ev.TicketID, usecase.DeviceInfo{})
					if err != nil {
						_ = writeQRTicketStatusUpdate(noiseConn, 0, string(ev.TicketID), gen.QRTicketStatusEXPIRED)
						registry.UnregisterPendingQR(ev.TicketID)
						continue
					}

					var curSeq updatelog.Seq
					if updateRepo != nil {
						curSeq, _ = updateRepo.CurrentSeq(ctx, sess.AccountID)
					}

					_ = writeQRLoginAck(noiseConn, 0, string(sess.ID), uint64(sess.DeviceID), uint64(sess.AccountID), int64(curSeq))

					activeConn.AccountID = sess.AccountID
					registry.Register(activeConn.Conn, sess.AccountID)
					registry.UnregisterPendingQR(ev.TicketID)
				}
			}
		}
	}()
}

func newHandler(
	kp *serverkey.ServerKeyPair,
	nodeID string,
	registry *transport.ConnectionRegistry,
	router *transport.MessageRouter,
	accountRepo account.Repository,
	emailAuthUC *usecase.EmailAuthUseCase,
	githubAuthUC *usecase.GithubAuthUseCase,
	qrLoginUC *usecase.QRLoginUseCase,
	sessionMgmtUC *usecase.SessionManagementUseCase,
	sessionUC *usecase.SessionUseCase,
	heartbeatUC *usecase.HeartbeatUseCase,
	messageUC *usecase.MessageUseCase,
	updateRepo updatelog.Repository,
	timeout time.Duration,
) transport.Handler {
	return func(rawConn *transport.Connection) {
		defer rawConn.Close()
		remote := rawConn.RemoteAddr().String()

		conn, err := noiseik.ServerHandshake(rawConn, kp.PrivateKey)
		if err != nil {
			logger.Log.WithFields(logrus.Fields{
				"remote": remote,
				"error":  err,
			}).Warn("Noise IK handshake failed")
			return
		}

		var (
			currentAccountID account.AccountID
			currentSessionID session.SessionID
			activeConn       *transport.ActiveConn
		)

		defer func() {
			if activeConn != nil {
				registry.Unregister(activeConn.ID)
			}
		}()

		entry := logger.Log.WithFields(logrus.Fields{
			"remote":     remote,
			"static_key": fmt.Sprintf("%x", conn.RemoteStaticKey()),
		})
		entry.Info("completed Noise IK handshake")

		ctx := logger.ToContext(context.Background(), entry)

		for {
			if timeout > 0 {
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
			}

			frame, err := conn.ReadFrame()
			if err != nil {
				logger.FromContext(ctx).WithField("error", err).Info("connection closed or read deadline exceeded")
				return
			}

			env := gen.GetRootAsEnvelope(frame, 0)
			reqCtx := logger.ToContext(ctx, logger.FromContext(ctx).WithField("request_id", env.RequestId()))

			switch env.BodyType() {
			case gen.BodyPing:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed Ping frame")
					return
				}
				ping := new(gen.Ping)
				ping.Init(unionTable.Bytes, unionTable.Pos)

				_ = heartbeatUC.HandlePing(reqCtx, currentSessionID, device.DeviceID(0))

				if err := writePong(conn, env.RequestId(), ping.Timestamp()); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write Pong")
					return
				}

			case gen.BodyNewSession:
				logger.FromContext(reqCtx).Info("requested NewSession")
				sess, err := sessionUC.NewSession(reqCtx, conn.RemoteStaticKey())
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("NewSession failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, err.Error())
					return
				}
				currentAccountID = sess.AccountID
				currentSessionID = sess.ID
				if activeConn != nil {
					registry.Unregister(activeConn.ID)
				}
				activeConn = registry.Register(conn, currentAccountID)

				var currentSeq updatelog.Seq
				if updateRepo != nil {
					currentSeq, _ = updateRepo.CurrentSeq(reqCtx, currentAccountID)
				}
				if err := writeNewSessionAck(conn, env.RequestId(), string(sess.ID), currentSeq); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write NewSessionAck")
					return
				}

			case gen.BodyResumeSession:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed ResumeSession frame")
					return
				}
				rsReq := new(gen.ResumeSession)
				rsReq.Init(unionTable.Bytes, unionTable.Pos)

				sessID := string(rsReq.SessionId())
				logger.FromContext(reqCtx).WithField("session_id", sessID).Info("requested ResumeSession")

				sess, err := sessionUC.ResumeSession(reqCtx, session.SessionID(sessID), conn.RemoteStaticKey())
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("ResumeSession failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, err.Error())
					return
				}
				currentAccountID = sess.AccountID
				currentSessionID = sess.ID
				if activeConn != nil {
					registry.Unregister(activeConn.ID)
				}
				activeConn = registry.Register(conn, currentAccountID)

				var currentSeq updatelog.Seq
				if updateRepo != nil {
					currentSeq, _ = updateRepo.CurrentSeq(reqCtx, currentAccountID)
				}
				if err := writeResumeSessionAck(conn, env.RequestId(), string(sess.ID), currentSeq); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write ResumeSessionAck")
					return
				}

			case gen.BodyRegisterAccount:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed RegisterAccount frame")
					return
				}
				regReq := new(gen.RegisterAccount)
				regReq.Init(unionTable.Bytes, unionTable.Pos)

				err := emailAuthUC.RequestCode(reqCtx, usecase.RequestCodeRequest{
					Email:     string(regReq.Email()),
					FirstName: string(regReq.FirstName()),
					LastName:  string(regReq.LastName()),
				})
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("RegisterAccount failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}

				var accID uint64
				if acc, err := accountRepo.FindByEmail(reqCtx, string(regReq.Email())); err == nil {
					accID = uint64(acc.ID)
				}

				if err := writeRegisterAccountAck(conn, env.RequestId(), accID); err != nil {
					return
				}

			case gen.BodyConfirmEmailCode:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed ConfirmEmailCode frame")
					return
				}
				cecReq := new(gen.ConfirmEmailCode)
				cecReq.Init(unionTable.Bytes, unionTable.Pos)

				sess, err := emailAuthUC.ConfirmCode(reqCtx, usecase.ConfirmCodeRequest{
					AccountID: account.AccountID(cecReq.AccountId()),
					Code:      string(cecReq.Code()),
					Device: usecase.DeviceInfo{
						PublicKey:   conn.RemoteStaticKey(),
						Fingerprint: string(cecReq.DeviceFingerprint()),
						DeviceName:  string(cecReq.DeviceName()),
						Platform:    string(cecReq.Platform()),
						OSVersion:   string(cecReq.OsVersion()),
						AppVersion:  string(cecReq.AppVersion()),
					},
				})
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("ConfirmEmailCode failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeINVALID_CODE, err.Error())
					return
				}

				currentAccountID = sess.AccountID
				currentSessionID = sess.ID
				if activeConn != nil {
					registry.Unregister(activeConn.ID)
				}
				activeConn = registry.Register(conn, currentAccountID)

				var currentSeq updatelog.Seq
				if updateRepo != nil {
					currentSeq, _ = updateRepo.CurrentSeq(reqCtx, currentAccountID)
				}

				if err := writeConfirmEmailCodeAck(conn, env.RequestId(), string(sess.ID), uint64(sess.DeviceID), int64(currentSeq)); err != nil {
					return
				}

			case gen.BodyCreateQRTicket:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed CreateQRTicket frame")
					return
				}
				cqrReq := new(gen.CreateQRTicket)
				cqrReq.Init(unionTable.Bytes, unionTable.Pos)

				ticket, err := qrLoginUC.CreateTicket(reqCtx, nodeID, conn.RemoteStaticKey())
				if err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}

				if activeConn == nil {
					activeConn = &transport.ActiveConn{
						Conn:         conn,
						DevicePubKey: conn.RemoteStaticKey(),
					}
				}

				registry.RegisterPendingQR(ticket.ID, activeConn)

				if err := writeCreateQRTicketAck(conn, env.RequestId(), string(ticket.ID), ticket.ExpiresAt.Unix()); err != nil {
					return
				}

			case gen.BodyScanQRTicket:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed ScanQRTicket frame")
					return
				}
				sqrReq := new(gen.ScanQRTicket)
				sqrReq.Init(unionTable.Bytes, unionTable.Pos)

				if err := qrLoginUC.Scan(reqCtx, qrlogin.TicketID(sqrReq.TicketId())); err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeQR_TICKET_NOT_FOUND, err.Error())
					return
				}

			case gen.BodyConfirmQRTicket:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed ConfirmQRTicket frame")
					return
				}
				cqrReq := new(gen.ConfirmQRTicket)
				cqrReq.Init(unionTable.Bytes, unionTable.Pos)

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}

				var devID device.DeviceID
				if activeConn != nil {
					devID = device.DeviceID(0)
				}

				if err := qrLoginUC.Confirm(reqCtx, qrlogin.TicketID(cqrReq.TicketId()), currentAccountID, devID); err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeQR_TICKET_NOT_FOUND, err.Error())
					return
				}

			case gen.BodyDenyQRTicket:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed DenyQRTicket frame")
					return
				}
				dqrReq := new(gen.DenyQRTicket)
				dqrReq.Init(unionTable.Bytes, unionTable.Pos)

				if err := qrLoginUC.Deny(reqCtx, qrlogin.TicketID(dqrReq.TicketId())); err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeQR_TICKET_NOT_FOUND, err.Error())
					return
				}

			case gen.BodyLogout:
				if currentSessionID != "" {
					_ = sessionMgmtUC.Logout(reqCtx, currentSessionID)
				}
				if activeConn != nil {
					registry.Unregister(activeConn.ID)
					activeConn = nil
				}
				currentAccountID = 0
				currentSessionID = ""
				_ = writeLogoutAck(conn, env.RequestId())

			case gen.BodyListSessions:
				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}
				sessions, err := sessionMgmtUC.ListSessions(reqCtx, currentAccountID)
				if err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}
				_ = writeListSessionsAck(conn, env.RequestId(), sessions, currentSessionID)

			case gen.BodyLogoutAllSessions:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed LogoutAllSessions frame")
					return
				}
				lasReq := new(gen.LogoutAllSessions)
				lasReq.Init(unionTable.Bytes, unionTable.Pos)

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}
				err := sessionMgmtUC.LogoutAll(reqCtx, currentAccountID, currentSessionID, lasReq.ExceptCurrent())
				if err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}
				_ = writeLogoutAllSessionsAck(conn, env.RequestId(), 1)

			case gen.BodySetSessionTTL:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed SetSessionTTL frame")
					return
				}
				sttlReq := new(gen.SetSessionTTL)
				sttlReq.Init(unionTable.Bytes, unionTable.Pos)

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}

				var months *int
				if sttlReq.HasMonths() {
					val := int(sttlReq.Months())
					months = &val
				}

				if err := sessionMgmtUC.SetSessionTTL(reqCtx, currentAccountID, months); err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeINVALID_SESSION_TTL, err.Error())
					return
				}
				_ = writeSetSessionTTLAck(conn, env.RequestId())

			case gen.BodySendMessage:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed SendMessage frame")
					return
				}
				smReq := new(gen.SendMessage)
				smReq.Init(unionTable.Bytes, unionTable.Pos)

				recipientID := account.AccountID(smReq.RecipientAccountId())
				clientMsgID := string(smReq.ClientMsgId())
				text := string(smReq.Text())

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}

				msg, _, err := messageUC.SendMessage(reqCtx, currentAccountID, recipientID, clientMsgID, text)
				if err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeINVALID_RECIPIENT, err.Error())
					return
				}

				if err := writeSendMessageAck(conn, env.RequestId(), msg.ClientMsgID, string(msg.ID), msg.CreatedAt.Unix()); err != nil {
					return
				}

			case gen.BodyGetDifference:
				unionTable := new(flatbuffers.Table)
				if !env.Body(unionTable) {
					logger.FromContext(reqCtx).Warn("sent malformed GetDifference frame")
					return
				}
				gdReq := new(gen.GetDifference)
				gdReq.Init(unionTable.Bytes, unionTable.Pos)

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}

				const diffLimit = 100
				updates, curSeq, hasMore, err := messageUC.GetDifference(
					reqCtx, currentAccountID, updatelog.Seq(gdReq.SinceSeq()), diffLimit,
				)
				if err != nil {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}
				if err := writeDifferenceAck(conn, env.RequestId(), updates, curSeq, hasMore); err != nil {
					return
				}

			default:
				logger.FromContext(reqCtx).WithField("body_type", env.BodyType()).Warn("unhandled body type")
			}
		}
	}
}

func writePong(conn *noiseik.Conn, requestID uint64, timestamp int64) error {
	b := flatbuffers.NewBuilder(64)
	gen.PongStart(b)
	gen.PongAddTimestamp(b, timestamp)
	pong := gen.PongEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyPong)
	gen.EnvelopeAddBody(b, pong)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeNewSessionAck(conn *noiseik.Conn, requestID uint64, sessionID string, currentSeq updatelog.Seq) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.NewSessionAckStart(b)
	gen.NewSessionAckAddSessionId(b, sessIDOffset)
	gen.NewSessionAckAddCurrentSeq(b, int64(currentSeq))
	ack := gen.NewSessionAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyNewSessionAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeResumeSessionAck(conn *noiseik.Conn, requestID uint64, sessionID string, currentSeq updatelog.Seq) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.ResumeSessionAckStart(b)
	gen.ResumeSessionAckAddSessionId(b, sessIDOffset)
	gen.ResumeSessionAckAddCurrentSeq(b, int64(currentSeq))
	ack := gen.ResumeSessionAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyResumeSessionAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeRegisterAccountAck(conn *noiseik.Conn, requestID uint64, accountID uint64) error {
	b := flatbuffers.NewBuilder(64)
	gen.RegisterAccountAckStart(b)
	gen.RegisterAccountAckAddAccountId(b, accountID)
	ack := gen.RegisterAccountAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyRegisterAccountAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeConfirmEmailCodeAck(conn *noiseik.Conn, requestID uint64, sessionID string, deviceID uint64, currentSeq int64) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.ConfirmEmailCodeAckStart(b)
	gen.ConfirmEmailCodeAckAddSessionId(b, sessIDOffset)
	gen.ConfirmEmailCodeAckAddDeviceId(b, deviceID)
	gen.ConfirmEmailCodeAckAddCurrentSeq(b, currentSeq)
	ack := gen.ConfirmEmailCodeAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyConfirmEmailCodeAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeCreateQRTicketAck(conn *noiseik.Conn, requestID uint64, ticketID string, expiresAt int64) error {
	b := flatbuffers.NewBuilder(128)
	tIDOffset := b.CreateString(ticketID)

	gen.CreateQRTicketAckStart(b)
	gen.CreateQRTicketAckAddTicketId(b, tIDOffset)
	gen.CreateQRTicketAckAddExpiresAt(b, expiresAt)
	ack := gen.CreateQRTicketAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyCreateQRTicketAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeQRTicketStatusUpdate(conn *noiseik.Conn, requestID uint64, ticketID string, status gen.QRTicketStatus) error {
	b := flatbuffers.NewBuilder(128)
	tIDOffset := b.CreateString(ticketID)

	gen.QRTicketStatusUpdateStart(b)
	gen.QRTicketStatusUpdateAddTicketId(b, tIDOffset)
	gen.QRTicketStatusUpdateAddStatus(b, status)
	upd := gen.QRTicketStatusUpdateEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyQRTicketStatusUpdate)
	gen.EnvelopeAddBody(b, upd)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeQRLoginAck(conn *noiseik.Conn, requestID uint64, sessionID string, deviceID, accountID uint64, currentSeq int64) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.QRLoginAckStart(b)
	gen.QRLoginAckAddSessionId(b, sessIDOffset)
	gen.QRLoginAckAddDeviceId(b, deviceID)
	gen.QRLoginAckAddAccountId(b, accountID)
	gen.QRLoginAckAddCurrentSeq(b, currentSeq)
	ack := gen.QRLoginAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyQRLoginAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeLogoutAck(conn *noiseik.Conn, requestID uint64) error {
	b := flatbuffers.NewBuilder(64)
	gen.LogoutAckStart(b)
	ack := gen.LogoutAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyLogoutAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeListSessionsAck(conn *noiseik.Conn, requestID uint64, sessions []session.Session, currentSessionID session.SessionID) error {
	b := flatbuffers.NewBuilder(512)

	type sessData struct {
		sID      flatbuffers.UOffsetT
		dName    flatbuffers.UOffsetT
		platform flatbuffers.UOffsetT
		osVer    flatbuffers.UOffsetT
	}
	sds := make([]sessData, len(sessions))
	for i, s := range sessions {
		sds[i] = sessData{
			sID:      b.CreateString(string(s.ID)),
			dName:    b.CreateString("Device"),
			platform: b.CreateString("macOS"),
			osVer:    b.CreateString("15.0"),
		}
	}

	infoOffsets := make([]flatbuffers.UOffsetT, len(sessions))
	for i, s := range sessions {
		gen.SessionInfoStart(b)
		gen.SessionInfoAddSessionId(b, sds[i].sID)
		gen.SessionInfoAddDeviceId(b, uint64(s.DeviceID))
		gen.SessionInfoAddDeviceName(b, sds[i].dName)
		gen.SessionInfoAddPlatform(b, sds[i].platform)
		gen.SessionInfoAddOsVersion(b, sds[i].osVer)
		gen.SessionInfoAddIsCurrent(b, s.ID == currentSessionID)
		gen.SessionInfoAddCreatedAt(b, s.CreatedAt.Unix())
		gen.SessionInfoAddLastActiveAt(b, s.LastActiveAt.Unix())
		infoOffsets[i] = gen.SessionInfoEnd(b)
	}

	gen.ListSessionsAckStartSessionsVector(b, len(infoOffsets))
	for i := len(infoOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(infoOffsets[i])
	}
	vec := b.EndVector(len(infoOffsets))

	gen.ListSessionsAckStart(b)
	gen.ListSessionsAckAddSessions(b, vec)
	ack := gen.ListSessionsAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyListSessionsAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeLogoutAllSessionsAck(conn *noiseik.Conn, requestID uint64, count int) error {
	b := flatbuffers.NewBuilder(64)
	gen.LogoutAllSessionsAckStart(b)
	gen.LogoutAllSessionsAckAddRevokedCount(b, int32(count))
	ack := gen.LogoutAllSessionsAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyLogoutAllSessionsAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeSetSessionTTLAck(conn *noiseik.Conn, requestID uint64) error {
	b := flatbuffers.NewBuilder(64)
	gen.SetSessionTTLAckStart(b)
	ack := gen.SetSessionTTLAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodySetSessionTTLAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeSendMessageAck(conn *noiseik.Conn, requestID uint64, clientMsgID, serverMsgID string, createdAt int64) error {
	b := flatbuffers.NewBuilder(128)
	cIDOffset := b.CreateString(clientMsgID)
	sIDOffset := b.CreateString(serverMsgID)

	gen.SendMessageAckStart(b)
	gen.SendMessageAckAddClientMsgId(b, cIDOffset)
	gen.SendMessageAckAddServerMsgId(b, sIDOffset)
	gen.SendMessageAckAddCreatedAt(b, createdAt)
	ack := gen.SendMessageAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodySendMessageAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeDifferenceAck(
	conn *noiseik.Conn,
	requestID uint64,
	updates []updatelog.Update,
	currentSeq updatelog.Seq,
	hasMore bool,
) error {
	b := flatbuffers.NewBuilder(512)

	type muData struct {
		srvID   flatbuffers.UOffsetT
		textOff flatbuffers.UOffsetT
		raw     *gen.MessageUpdate
	}
	mds := make([]muData, len(updates))
	for i, u := range updates {
		raw := gen.GetRootAsMessageUpdate(u.Payload, 0)
		mds[i] = muData{
			srvID:   b.CreateString(string(raw.ServerMsgId())),
			textOff: b.CreateString(string(raw.Text())),
			raw:     raw,
		}
	}

	muOffsets := make([]flatbuffers.UOffsetT, len(updates))
	for i, md := range mds {
		gen.MessageUpdateStart(b)
		gen.MessageUpdateAddServerMsgId(b, md.srvID)
		gen.MessageUpdateAddSenderAccountId(b, md.raw.SenderAccountId())
		gen.MessageUpdateAddText(b, md.textOff)
		gen.MessageUpdateAddCreatedAt(b, md.raw.CreatedAt())
		gen.MessageUpdateAddSeqNo(b, int64(updates[i].Seq))
		muOffsets[i] = gen.MessageUpdateEnd(b)
	}

	gen.DifferenceAckStartUpdatesVector(b, len(muOffsets))
	for i := len(muOffsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(muOffsets[i])
	}
	updatesVec := b.EndVector(len(muOffsets))

	gen.DifferenceAckStart(b)
	gen.DifferenceAckAddUpdates(b, updatesVec)
	gen.DifferenceAckAddCurrentSeq(b, int64(currentSeq))
	gen.DifferenceAckAddHasMore(b, hasMore)
	ack := gen.DifferenceAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyDifferenceAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeError(conn *noiseik.Conn, requestID uint64, code gen.ErrorCode, msg string) error {
	b := flatbuffers.NewBuilder(128)
	msgOffset := b.CreateString(msg)

	gen.ErrorStart(b)
	gen.ErrorAddCode(b, code)
	gen.ErrorAddMessage(b, msgOffset)
	errTable := gen.ErrorEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyError)
	gen.EnvelopeAddBody(b, errTable)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}
