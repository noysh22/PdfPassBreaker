package breaker

import (
	"fmt"
	"os"

	pdf "github.com/unidoc/unidoc/pdf/model"
)

// Breaker ...
// interface representing a PDF breaker object
type Breaker interface {
	// New(filename string, passMaxLength uint) (*Breaker, error)
	BruteForce() ([]byte, error)
	IsEncrypted() (bool, error)
}

// PDFBreaker ...
type PDFBreaker struct {
	pdfReader *pdf.PdfReader
}

// NewBreaker ...
// Create new PDF breaker
func NewBreaker(filename string, passMaxLength uint) (Breaker, error) {
	file, err := os.Open(filename)
	if nil != err {
		// panic()
		return nil, fmt.Errorf("Error opening file: %v", err)
	}
	defer file.Close()

	reader, err := pdf.NewPdfReader(file)
	if nil != err {
		// panic()
		return nil, fmt.Errorf("Error creating pdf reader: %v", err)
	}

	breaker := &PDFBreaker{pdfReader: reader}
	return breaker, nil
}

// BruteForce ...
func (breaker *PDFBreaker) BruteForce() ([]byte, error) {
	return make([]byte, 10), nil
}

// IsEncrypted ...
func (breaker *PDFBreaker) IsEncrypted() (bool, error) {
	return breaker.pdfReader.IsEncrypted()
}
