package wireauthgrpc

// Protocol layout (see README.md "Protocol invariants" for the frozen
// contract — nothing here changes without a major version bump).
//
// Stage 1 — client -> server:
//   offset 0, size 4  : cmd            (u32 LE, always cmd1)
//   offset 4, size 16 : client_nonce   (random)
// Stage 1 — server -> client:
//   offset 0, size 16  : server_nonce  (random)
//   offset 16, size 256: signature     (RSA-PKCS1v15-SHA256 over client_nonce||server_nonce)
//
// Stage 2 — client -> server:
//   offset 0, size 4  : cmd            (u32 LE, always cmd2)
//   offset 4, size 65 : client_pubkey  (ECDH P-256 uncompressed, 0x04||X||Y)
// Stage 2 — server -> client:
//   offset 0, size 65 : server_pubkey  (same format)
//
// KDF: session_key = SHA256(shared_secret || client_nonce || server_nonce)
//
// AEAD record (post-handshake, either direction). Unlike wireauth's
// WebSocket framing (where the transport already delivers whole
// messages), a raw net.Conn is a byte stream with no message boundaries,
// so each record is explicitly length-prefixed on the wire:
//
//   offset 0, size 4   : record_len    (u32 BE) — length of everything after this field
//   offset 4, size 8   : seq           (u64 BE)
//   offset 12, size 12 : nonce         (random, per-record)
//   offset 24, size N  : ciphertext+tag (AES-256-GCM, AAD = seq bytes, NOT record_len)
//
// record_len = 8 (seq) + 12 (nonce) + len(ciphertext+tag). It exists only
// to delimit records on the byte stream and is deliberately excluded from
// the AEAD's associated data — it is transport framing, not
// protocol-meaningful data (unlike seq, which is also the GCM AAD and
// therefore authenticated).

const (
	cmd1 uint32 = 1
	cmd2 uint32 = 2

	nonceSize      = 16 // client_nonce / server_nonce
	rsaSigSize     = 256
	ecdhPubKeySize = 65 // uncompressed P-256 point: 0x04 || X(32) || Y(32)
	aesKeySize     = 32 // AES-256
	gcmNonceSize   = 12
	gcmTagSize     = 16
	seqFieldSize   = 8
	cmdFieldSize   = 4
	lenFieldSize   = 4 // record_len prefix on the wire, see AEAD record layout above

	// maxRecordLen bounds record_len to reject obviously-bogus or hostile
	// length prefixes before allocating a buffer for them. Must be >=
	// maxRecordPlaintext + GCM overhead (see secure_conn.go).
	maxRecordLen = 1 << 20 // 1 MiB

	stage1ClientMsgSize = cmdFieldSize + nonceSize      // 20
	stage1ServerMsgSize = nonceSize + rsaSigSize        // 272
	stage2ClientMsgSize = cmdFieldSize + ecdhPubKeySize // 69
	stage2ServerMsgSize = ecdhPubKeySize                // 65

	// minRecordBodySize = seq + nonce + tag, with zero-length plaintext.
	// This is the minimum value of record_len (i.e. everything after the
	// 4-byte length prefix).
	minRecordBodySize = seqFieldSize + gcmNonceSize + gcmTagSize
)
