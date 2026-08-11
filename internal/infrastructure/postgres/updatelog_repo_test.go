package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/updatelog"
)

func TestUpdateLogRepo_Append_SeqIncreasing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUpdateLogRepository(db)
	accountID := account.AccountID(10)

	mock.ExpectQuery(`INSERT INTO account_seq_counters`).
		WithArgs(accountID).
		WillReturnRows(sqlmock.NewRows([]string{"current_seq"}).AddRow(int64(1)))

	mock.ExpectExec(`INSERT INTO account_updates`).
		WithArgs(accountID, int64(1), updatelog.KindMessage, []byte("payload1")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	seq1, err := repo.Append(context.Background(), accountID, updatelog.KindMessage, []byte("payload1"))
	if err != nil {
		t.Fatalf("Append 1 failed: %v", err)
	}
	if seq1 != 1 {
		t.Fatalf("expected seq 1, got %d", seq1)
	}

	mock.ExpectQuery(`INSERT INTO account_seq_counters`).
		WithArgs(accountID).
		WillReturnRows(sqlmock.NewRows([]string{"current_seq"}).AddRow(int64(2)))

	mock.ExpectExec(`INSERT INTO account_updates`).
		WithArgs(accountID, int64(2), updatelog.KindMessage, []byte("payload2")).
		WillReturnResult(sqlmock.NewResult(1, 1))

	seq2, err := repo.Append(context.Background(), accountID, updatelog.KindMessage, []byte("payload2"))
	if err != nil {
		t.Fatalf("Append 2 failed: %v", err)
	}
	if seq2 != 2 {
		t.Fatalf("expected seq 2, got %d", seq2)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUpdateLogRepo_Append_Concurrent(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUpdateLogRepository(db)
	accountID := account.AccountID(20)

	const n = 5
	for i := 1; i <= n; i++ {
		mock.ExpectQuery(`INSERT INTO account_seq_counters`).
			WithArgs(accountID).
			WillReturnRows(sqlmock.NewRows([]string{"current_seq"}).AddRow(int64(i)))

		mock.ExpectExec(`INSERT INTO account_updates`).
			WithArgs(accountID, int64(i), updatelog.KindMessage, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)

	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()
			_, err := repo.Append(context.Background(), accountID, updatelog.KindMessage, []byte("concurrent"))
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent Append failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUpdateLogRepo_ListSince(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUpdateLogRepository(db)
	accountID := account.AccountID(30)
	now := time.Now()

	mock.ExpectQuery(`SELECT COALESCE\(MAX\(seq\), 0\)`).
		WithArgs(accountID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(3)))

	rows := sqlmock.NewRows([]string{"seq", "kind", "payload", "created_at"}).
		AddRow(int64(2), uint8(1), []byte("p2"), now).
		AddRow(int64(3), uint8(1), []byte("p3"), now)

	mock.ExpectQuery(`SELECT seq, kind, payload, created_at FROM account_updates`).
		WithArgs(accountID, int64(1), 3).
		WillReturnRows(rows)

	updates, curSeq, hasMore, err := repo.ListSince(context.Background(), accountID, updatelog.Seq(1), 2)
	if err != nil {
		t.Fatalf("ListSince failed: %v", err)
	}
	if curSeq != 3 {
		t.Fatalf("expected curSeq 3, got %d", curSeq)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d", len(updates))
	}
	if hasMore {
		t.Fatal("expected hasMore = false when len(updates) == limit")
	}
	if updates[0].Seq != 2 || updates[1].Seq != 3 {
		t.Fatalf("unexpected update seqs: %d, %d", updates[0].Seq, updates[1].Seq)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUpdateLogRepo_ListSince_HasMore(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewUpdateLogRepository(db)
	accountID := account.AccountID(40)
	now := time.Now()

	mock.ExpectQuery(`SELECT COALESCE\(MAX\(seq\), 0\)`).
		WithArgs(accountID).
		WillReturnRows(sqlmock.NewRows([]string{"coalesce"}).AddRow(int64(5)))

	rows := sqlmock.NewRows([]string{"seq", "kind", "payload", "created_at"}).
		AddRow(int64(1), uint8(1), []byte("p1"), now).
		AddRow(int64(2), uint8(1), []byte("p2"), now).
		AddRow(int64(3), uint8(1), []byte("p3"), now)

	mock.ExpectQuery(`SELECT seq, kind, payload, created_at FROM account_updates`).
		WithArgs(accountID, int64(0), 3).
		WillReturnRows(rows)

	updates, curSeq, hasMore, err := repo.ListSince(context.Background(), accountID, updatelog.Seq(0), 2)
	if err != nil {
		t.Fatalf("ListSince failed: %v", err)
	}
	if curSeq != 5 {
		t.Fatalf("expected curSeq 5, got %d", curSeq)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates sliced to limit, got %d", len(updates))
	}
	if !hasMore {
		t.Fatal("expected hasMore = true when 3 rows returned for limit=2")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
