package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/airlance/api/internal/config"
	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/logger"
	"github.com/airlance/api/internal/infrastructure/memory"
	"github.com/airlance/api/internal/infrastructure/serverkey"
	"github.com/airlance/api/internal/noiseik"
	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	"github.com/airlance/api/internal/transport"
	"github.com/airlance/api/internal/usecase"
	flatbuffers "github.com/google/flatbuffers/go"
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

		registry := transport.NewConnectionRegistry()
		router := transport.NewMessageRouter()
		defer router.Close()

		sessionRepo := memory.NewSessionRepository()
		sessionUC := usecase.NewSessionUseCase(sessionRepo, nil)
		heartbeatUC := usecase.NewHeartbeatUseCase(nil)
		messageUC := usecase.NewMessageUseCase(nil, nil)

		l := transport.NewListener(cfg.Server.Addr, newHandler(kp, registry, router, sessionUC, heartbeatUC, messageUC, cfg.Server.HeartbeatTimeout))
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

		active := registry.Register(conn)
		defer registry.Unregister(active.ID)

		entry := logger.Log.WithFields(logrus.Fields{
			"remote":     remote,
			"conn_id":    active.ID,
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
				if err := writeNewSessionAck(conn, env.RequestId(), string(sess.ID)); err != nil {
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
				if err := writeResumeSessionAck(conn, env.RequestId(), string(sess.ID)); err != nil {
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

				msg, err := messageUC.SendMessage(reqCtx, account.AccountID(0), recipientID, clientMsgID, text)
				if err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("SendMessage failed")
					_ = writeError(conn, env.RequestId(), gen.ErrorCodeINVALID_RECIPIENT, err.Error())
					return
				}

				if err := writeSendMessageAck(conn, env.RequestId(), msg.ClientMsgID, string(msg.ID), msg.CreatedAt.Unix()); err != nil {
					logger.FromContext(reqCtx).WithField("error", err).Warn("failed to write SendMessageAck")
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

func writeNewSessionAck(conn *noiseik.Conn, requestID uint64, sessionID string) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.NewSessionAckStart(b)
	gen.NewSessionAckAddSessionId(b, sessIDOffset)
	ack := gen.NewSessionAckEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, requestID)
	gen.EnvelopeAddBodyType(b, gen.BodyNewSessionAck)
	gen.EnvelopeAddBody(b, ack)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	return conn.WriteFrame(b.FinishedBytes())
}

func writeResumeSessionAck(conn *noiseik.Conn, requestID uint64, sessionID string) error {
	b := flatbuffers.NewBuilder(128)
	sessIDOffset := b.CreateString(sessionID)

	gen.ResumeSessionAckStart(b)
	gen.ResumeSessionAckAddSessionId(b, sessIDOffset)
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
