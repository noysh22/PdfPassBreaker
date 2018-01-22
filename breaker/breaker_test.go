package breaker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const TestPdf = "./test_file.pdf"
const MaxPassLen = 6

func TestNewBreaker(t *testing.T) {
	breaker, err := NewBreaker(TestPdf, MaxPassLen)

	assert.Nil(t, err)
	assert.NotNil(t, breaker)
}

func TestIsEncrypted(t *testing.T) {
	breaker, err := NewBreaker(TestPdf, MaxPassLen)

	assert.Nil(t, err)

	isEncrypted, err := breaker.IsEncrypted()
	assert.Nil(t, err)
	assert.True(t, isEncrypted)
}
