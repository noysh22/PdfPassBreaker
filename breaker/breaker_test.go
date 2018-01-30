package breaker_test

import (
	"testing"
	"time"

	. "github.com/noysh22/pdf_breaker/breaker"
	"github.com/stretchr/testify/assert"
)

const (
	TestProtected      = "./tests_files/test_protected.pdf"
	TestUnprotectedPdf = "./tests_files/test_notprotected.pdf"
	MaxPassLen         = uint(6)
	DefaultTimeout     = 30 * time.Second
	RunRecursive       = true // Running recurrsive solution (more efficient)
)

func setupTestCase(pdfFile string,
	maxPassLen uint,
	t *testing.T) (Breaker, func(*testing.T)) {

	t.Logf("setup test case <%s>", t.Name())
	breaker, err := NewBreaker(pdfFile, maxPassLen)

	assert.Nil(t, err)
	assert.NotNil(t, breaker)

	tearDown := func(t *testing.T) {
		t.Logf("teardown test case <%s>", t.Name())
	}

	return breaker, tearDown
}

func TestNewBreaker(t *testing.T) {
	breaker, err := NewBreaker(TestProtected, MaxPassLen)

	assert.Nil(t, err)
	assert.NotNil(t, breaker)

	// convert breaker to *PDFBreaker
	pdf, _ := breaker.(*PDFBreaker)
	assert.Equal(t, MaxPassLen, pdf.GetPassMaxLength(), "PassMaxLength value in invalid")
}

func TestIsEncrypted(t *testing.T) {
	breaker, tearDown := setupTestCase(TestProtected, MaxPassLen, t)
	defer tearDown(t)

	isEncrypted, err := breaker.IsEncrypted()
	assert.Nil(t, err)
	assert.True(t, isEncrypted)
}

func TestBruteForceUnProtectedFile(t *testing.T) {
	breaker, tearDown := setupTestCase(TestUnprotectedPdf, MaxPassLen, t)
	defer tearDown(t)

	_, err := breaker.BruteForce(DefaultTimeout, RunRecursive)

	assert.NotNil(t, err)
	assert.Equal(t, "Cannot brute force unprotected file", err.Error())
}

func TestBruteForceSanity(t *testing.T) {
	breaker, tearDown := setupTestCase(TestProtected, MaxPassLen, t)
	defer tearDown(t)

	expectedResult := []byte("123456")
	pass, err := breaker.BruteForce(DefaultTimeout, RunRecursive)

	assert.Nil(t, err)
	assert.Equal(t, expectedResult, pass)
	t.Logf("passwords cracked: %s", pass)
}
func TestBruteForceSequential(t *testing.T) {
	breaker, tearDown := setupTestCase(TestProtected, MaxPassLen, t)
	defer tearDown(t)

	expectedResult := []byte("123456")
	pass, err := breaker.BruteForce(5*time.Minute, false)

	assert.Nil(t, err)
	assert.Equal(t, expectedResult, pass)
	t.Logf("passwords cracked: %s", pass)
}

func TestBruteForceTimeout(t *testing.T) {
	breaker, tearDown := setupTestCase(TestProtected, MaxPassLen, t)
	defer tearDown(t)

	pass, err := breaker.BruteForce(2*time.Second, RunRecursive)

	assert.Nil(t, pass)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Timeout: true")
}
