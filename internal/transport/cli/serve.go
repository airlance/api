package cli

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/domain/updatelog"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/airlance/api/internal/infrastructure/memory"
	"github.com/airlance/api/internal/infrastructure/postgres"
	"github.com/airlance/api/internal/infrastructure/serverkey"
	"github.com/airlance/api/internal/noiseik"
	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	"github.com/airlance/api/internal/transport"
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
		if err := db.PingContext(cmd.Context()); err != nil {
			return fmt.Errorf("server: ping db failed: %w", err)
		}

		uow := postgres.NewUnitOfWork(db)
		updateRepo := postgres.NewUpdateLogRepository(db)

		registry := transport.NewConnectionRegistry()
		router := transport.NewMessageRouter()
		defer router.Close()

		sessionRepo := memory.NewSessionRepository()
		sessionUC := usecase.NewSessionUseCase(sessionRepo, nil)
		heartbeatUC := usecase.NewHeartbeatUseCase(nil)
		messageUC := usecase.NewMessageUseCase(uow, updateRepo, registry)

		l := transport.NewListener(cfg.Server.Addr, newHandler(kp, registry, router, sessionUC, heartbeatUC, messageUC, updateRepo, cfg.Server.HeartbeatTimeout))
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

func newHandler(
	kp *serverkey.ServerKeyPair,
	registry *transport.ConnectionRegistry,
	router *transport.MessageRouter,
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
				logger.FromContext(reqCtx).WithField("timestamp", ping.Timestamp()).Debug("received Ping")

				_ = heartbeatUC.HandlePing(reqCtx, device.DeviceID(0))

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

				logger.FromContext(reqCtx).WithFields(logrus.Fields{
					"recipient_id":  recipientID,
					"client_msg_id": clientMsgID,
				}).Info("received SendMessage")

				if currentAccountID == 0 {
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeSESSION_NOT_FOUND, "not authenticated")
					return
				}

				msg, _, err := messageUC.SendMessage(reqCtx, currentAccountID, recipientID, clientMsgID, text)
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("SendMessage failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeINVALID_RECIPIENT, err.Error())
					return
				}

				if err := writeSendMessageAck(conn, env.RequestId(), msg.ClientMsgID, string(msg.ID), msg.CreatedAt.Unix()); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write SendMessageAck")
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
					logger.FromContext(reqCtx).WithField("error", err).Warn("GetDifference failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeUNKNOWN, err.Error())
					return
				}
				if err := writeDifferenceAck(conn, env.RequestId(), updates, curSeq, hasMore); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write DifferenceAck")
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
