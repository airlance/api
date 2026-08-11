package protocol_test

import (
	"testing"

	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	flatbuffers "github.com/google/flatbuffers/go"
)

func TestEnvelopePingRoundtrip(t *testing.T) {
	b := flatbuffers.NewBuilder(64)

	gen.PingStart(b)
	gen.PingAddTimestamp(b, 1234567890)
	ping := gen.PingEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, 42)
	gen.EnvelopeAddBodyType(b, gen.BodyPing)
	gen.EnvelopeAddBody(b, ping)
	env := gen.EnvelopeEnd(b)

	b.Finish(env)
	buf := b.FinishedBytes()

	decoded := gen.GetRootAsEnvelope(buf, 0)
	if decoded.RequestId() != 42 {
		t.Fatalf("expected request_id 42, got %d", decoded.RequestId())
	}
	if decoded.BodyType() != gen.BodyPing {
		t.Fatalf("expected body type Ping")
	}

	unionTable := new(flatbuffers.Table)
	if !decoded.Body(unionTable) {
		t.Fatal("failed to unpack union body")
	}
	pingDecoded := new(gen.Ping)
	pingDecoded.Init(unionTable.Bytes, unionTable.Pos)
	if pingDecoded.Timestamp() != 1234567890 {
		t.Fatalf("expected timestamp 1234567890, got %d", pingDecoded.Timestamp())
	}
}

func TestUnionBodyIndicesAreStable(t *testing.T) {
	cases := []struct {
		name string
		got  gen.Body
		want gen.Body
	}{
		{"Ping", gen.BodyPing, 1},
		{"Pong", gen.BodyPong, 2},
		{"NewSession", gen.BodyNewSession, 3},
		{"ResumeSession", gen.BodyResumeSession, 4},
		{"RegisterAccount", gen.BodyRegisterAccount, 5},
		{"RegisterAccountAck", gen.BodyRegisterAccountAck, 6},
		{"ConfirmEmailCode", gen.BodyConfirmEmailCode, 7},
		{"ConfirmEmailCodeAck", gen.BodyConfirmEmailCodeAck, 8},
		{"Error", gen.BodyError, 9},
		{"NewSessionAck", gen.BodyNewSessionAck, 10},
		{"ResumeSessionAck", gen.BodyResumeSessionAck, 11},
		{"SendMessage", gen.BodySendMessage, 12},
		{"SendMessageAck", gen.BodySendMessageAck, 13},
		{"MessageUpdate", gen.BodyMessageUpdate, 14},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Fatalf("union index for %s changed: got %d, want %d — this breaks wire compatibility with old clients", c.name, c.got, c.want)
		}
	}
}

func TestNewSessionRoundtrip(t *testing.T) {
	b := flatbuffers.NewBuilder(64)

	gen.NewSessionStart(b)
	gen.NewSessionAddDeviceId(b, 777)
	ns := gen.NewSessionEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, 1)
	gen.EnvelopeAddBodyType(b, gen.BodyNewSession)
	gen.EnvelopeAddBody(b, ns)
	env := gen.EnvelopeEnd(b)

	b.Finish(env)
	buf := b.FinishedBytes()

	decoded := gen.GetRootAsEnvelope(buf, 0)
	if decoded.BodyType() != gen.BodyNewSession {
		t.Fatalf("expected body type NewSession")
	}

	unionTable := new(flatbuffers.Table)
	if !decoded.Body(unionTable) {
		t.Fatal("failed to unpack union body")
	}
	nsDecoded := new(gen.NewSession)
	nsDecoded.Init(unionTable.Bytes, unionTable.Pos)
	if nsDecoded.DeviceId() != 777 {
		t.Fatalf("expected device_id 777, got %d", nsDecoded.DeviceId())
	}
}

func TestRegisterAccountRoundtrip(t *testing.T) {
	b := flatbuffers.NewBuilder(128)

	emailOffset := b.CreateString("alice@example.com")
	fnOffset := b.CreateString("Alice")
	lnOffset := b.CreateString("Smith")

	gen.RegisterAccountStart(b)
	gen.RegisterAccountAddEmail(b, emailOffset)
	gen.RegisterAccountAddFirstName(b, fnOffset)
	gen.RegisterAccountAddLastName(b, lnOffset)
	reg := gen.RegisterAccountEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, 100)
	gen.EnvelopeAddBodyType(b, gen.BodyRegisterAccount)
	gen.EnvelopeAddBody(b, reg)
	env := gen.EnvelopeEnd(b)

	b.Finish(env)
	buf := b.FinishedBytes()

	decoded := gen.GetRootAsEnvelope(buf, 0)
	if decoded.BodyType() != gen.BodyRegisterAccount {
		t.Fatalf("expected body type RegisterAccount")
	}

	unionTable := new(flatbuffers.Table)
	if !decoded.Body(unionTable) {
		t.Fatal("failed to unpack union body")
	}
	regDecoded := new(gen.RegisterAccount)
	regDecoded.Init(unionTable.Bytes, unionTable.Pos)
	if string(regDecoded.Email()) != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %s", regDecoded.Email())
	}
	if string(regDecoded.FirstName()) != "Alice" {
		t.Fatalf("expected first_name Alice, got %s", regDecoded.FirstName())
	}
	if string(regDecoded.LastName()) != "Smith" {
		t.Fatalf("expected last_name Smith, got %s", regDecoded.LastName())
	}
}

func TestErrorFrameRoundtrip(t *testing.T) {
	b := flatbuffers.NewBuilder(128)

	msgOffset := b.CreateString("invalid code")

	gen.ErrorStart(b)
	gen.ErrorAddCode(b, gen.ErrorCodeINVALID_CODE)
	gen.ErrorAddMessage(b, msgOffset)
	errBody := gen.ErrorEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddRequestId(b, 101)
	gen.EnvelopeAddBodyType(b, gen.BodyError)
	gen.EnvelopeAddBody(b, errBody)
	env := gen.EnvelopeEnd(b)

	b.Finish(env)
	buf := b.FinishedBytes()

	decoded := gen.GetRootAsEnvelope(buf, 0)
	if decoded.BodyType() != gen.BodyError {
		t.Fatalf("expected body type Error")
	}

	unionTable := new(flatbuffers.Table)
	if !decoded.Body(unionTable) {
		t.Fatal("failed to unpack union body")
	}
	errDecoded := new(gen.Error)
	errDecoded.Init(unionTable.Bytes, unionTable.Pos)
	if errDecoded.Code() != gen.ErrorCodeINVALID_CODE {
		t.Fatalf("expected error code INVALID_CODE, got %v", errDecoded.Code())
	}
	if string(errDecoded.Message()) != "invalid code" {
		t.Fatalf("expected message 'invalid code', got %s", errDecoded.Message())
	}
}
