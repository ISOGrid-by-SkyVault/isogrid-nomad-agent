package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "argon2id$v=19$") || strings.Contains(hash, "correct") {
		t.Fatalf("unexpected encoding %q", hash)
	}
	if !VerifyPassword(hash, "correct horse battery") {
		t.Fatal("the right password was refused")
	}
	if VerifyPassword(hash, "correct horse batterz") {
		t.Fatal("a wrong password was accepted")
	}
	other, _ := HashPassword("correct horse battery")
	if other == hash {
		t.Fatal("two hashes of one password are equal: no salt")
	}
	for _, bad := range []string{"", "plain", "argon2id$v=19$m=1,t=1,p=0$AA$AA", "bcrypt$x$y$z$w"} {
		if VerifyPassword(bad, "x") {
			t.Fatalf("malformed hash %q verified", bad)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	if CheckPassword("short") == nil {
		t.Fatal("a short password passed")
	}
	if CheckPassword(strings.Repeat("a", MaxPasswordLength+1)) == nil {
		t.Fatal("an oversized password passed")
	}
	if err := CheckPassword("twelve chars!"); err != nil {
		t.Fatal(err)
	}
}

// RFC 6238, appendix B, SHA-1 rows, truncated to six digits.
func TestTOTPVectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890"
	cases := map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"}
	for at, want := range cases {
		got, err := TOTPCode(secret, time.Unix(at, 0))
		if err != nil || got != want {
			t.Fatalf("at %d: got %q (%v), want %q", at, got, err, want)
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_015, 0)
	code, _ := TOTPCode(secret, now)
	if !VerifyTOTP(secret, code, now) || !VerifyTOTP(secret, " "+code[:3]+" "+code[3:], now) {
		t.Fatal("the current code was refused")
	}
	if !VerifyTOTP(secret, code, now.Add(30*time.Second)) || !VerifyTOTP(secret, code, now.Add(-30*time.Second)) {
		t.Fatal("a neighbouring step was refused")
	}
	if VerifyTOTP(secret, code, now.Add(2*time.Minute)) {
		t.Fatal("an old code was accepted")
	}
	if VerifyTOTP(secret, "12345", now) || VerifyTOTP("not base32 !", code, now) {
		t.Fatal("a malformed code or secret was accepted")
	}
	uri := TOTPURI(secret, "ops", "ISOGrid Nomad")
	if !strings.HasPrefix(uri, "otpauth://totp/ISOGrid%20Nomad:ops?") || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("uri %q", uri)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(1_800_000_000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < limiterFree-1; i++ {
		l.Fail("k")
		if l.Blocked("k") != 0 {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	l.Fail("k")
	if got := l.Blocked("k"); got != limiterBase {
		t.Fatalf("after %d failures: blocked %s, want %s", limiterFree, got, limiterBase)
	}
	l.Fail("k")
	if got := l.Blocked("k"); got != 2*limiterBase {
		t.Fatalf("lock did not double: %s", got)
	}
	if l.Blocked("other") != 0 {
		t.Fatal("another key is blocked")
	}
	now = now.Add(2 * limiterBase)
	if l.Blocked("k") != 0 {
		t.Fatal("still blocked after the lock")
	}
	for i := 0; i < 40; i++ {
		l.Fail("k")
	}
	if got := l.Blocked("k"); got != limiterMax {
		t.Fatalf("lock not capped: %s", got)
	}
	l.Succeed("k")
	if l.Blocked("k") != 0 {
		t.Fatal("blocked after a success")
	}
}

func TestTokens(t *testing.T) {
	a, ha, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, hb, _ := NewToken()
	if a == b || ha == hb || HashToken(a) != ha || len(ha) != 64 || ha == a {
		t.Fatal("tokens or hashes are not what they should be")
	}
}
