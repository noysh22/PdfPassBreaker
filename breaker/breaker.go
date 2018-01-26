package breaker

import (
	"fmt"
	"log"
	"os"
	"time"

	pdf "github.com/unidoc/unidoc/pdf/model"
)

const (
	cInitChar = 0x30
)

var (
	gChars = []byte("0123456789")
	gInfo  *log.Logger
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
	pdfReader     *pdf.PdfReader
	passMaxLength uint
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

	gInfo = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	breaker := &PDFBreaker{pdfReader: reader, passMaxLength: passMaxLength}
	return breaker, nil
}

func initPasswordSlice(password []byte, initVal byte) {
	for i := 0; i < len(password); i++ {
		password[i] = initVal
	}
}

// crackRec ...
// Try crack a given passwrod buffer with all the passwords combinations
// possible for the size of the buffer
// function is executing in a recursive way
func crackRec(password []byte, index int, size int, validate func([]byte) bool) bool {
	// Iterate over all the options chars possible in a password
	for i := 0; i < len(gChars); i++ {
		// set current index to a gives char
		password[index] = gChars[i]
		// keep calling crack as long as index is smaller that size
		if size-1 > index {
			// Check pass recursive
			if crackRec(password, index+1, size, validate) {
				return true
			}
			// try to validate only if are checking a full password
			// To save validate calls
		} else if index == size-1 && validate(password) {
			return true
		}
	}
	return false
}

// BruteForce ...
func (breaker *PDFBreaker) BruteForce() ([]byte, error) {
	if isEncrypted, _ := breaker.IsEncrypted(); !isEncrypted {
		return nil, fmt.Errorf("Cannot brute force unprotected file")
	}

	password := make([]byte, breaker.passMaxLength)
	initPasswordSlice(password, cInitChar)

	checkPassword := func([]byte) bool {
		isCorrect, _, _ := breaker.pdfReader.CheckAccessRights(password)
		return isCorrect
	}

	start := time.Now()
	if !crackRec(password, 0, len(password), checkPassword) {
		return nil, fmt.Errorf("Failed brute forcing the password")
	}
	crackTime := time.Since(start)
	gInfo.Printf("Cracking password took %s\n", crackTime)

	_, accessRights, err := breaker.pdfReader.CheckAccessRights(password)

	if nil != err {
		fmt.Println("Failed getting access rights")
		gInfo.Println("Failed getting access rights")
	} else {
		fmt.Printf("Access rights: %v\b", accessRights)
		gInfo.Printf("Access rights: %v\b", accessRights)
	}

	return password, nil
}

// IsEncrypted ...
func (breaker *PDFBreaker) IsEncrypted() (bool, error) {
	return breaker.pdfReader.IsEncrypted()
}

// GetPassMaxLength ...
func (breaker *PDFBreaker) GetPassMaxLength() uint {
	return breaker.passMaxLength
}
