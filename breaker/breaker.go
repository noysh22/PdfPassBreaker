package breaker

import (
	"fmt"
	"log"
	"math"
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
	BruteForce(time.Duration, bool) ([]byte, error)
	IsEncrypted() (bool, error)
}

// PDFBreaker ...
type PDFBreaker struct {
	pdfReader     *pdf.PdfReader
	passMaxLength uint
	isTimedout    bool
}

// NewBreaker ...
// Create new PDF breaker
func NewBreaker(filename string, passMaxLength uint) (Breaker, error) {
	file, err := os.Open(filename)
	if nil != err {
		return nil, fmt.Errorf("Error opening file: %v", err)
	}
	defer file.Close()

	reader, err := pdf.NewPdfReader(file)
	if nil != err {
		return nil, fmt.Errorf("Error creating pdf reader: %v", err)
	}

	gInfo = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	breaker := &PDFBreaker{pdfReader: reader, passMaxLength: passMaxLength, isTimedout: false}
	return breaker, nil
}

func initPasswordSlice(password []byte, initVal byte) {
	for i := 0; i < len(password); i++ {
		password[i] = initVal
	}
}

func (breaker *PDFBreaker) shouldTimeout(timeoutChan chan bool) bool {
	if breaker.isTimedout {
		return true
	}

	select {
	case <-timeoutChan:
		breaker.isTimedout = true
		return true
	default:
		return false
	}
}

// crackRec ...
// Try crack a given passwrod buffer with all the passwords combinations
// possible for the size of the buffer
// function is executing in a recursive way
func (breaker *PDFBreaker) crackRec(
	password []byte,
	index int,
	size int,
	validate func([]byte) bool,
	timeoutChan chan bool) bool {

	timedout := breaker.shouldTimeout(timeoutChan)
	// Iterate over all the options chars possible in a password
	for i := 0; i < len(gChars) && !timedout; i++ {
		// set current index to a gives char
		password[index] = gChars[i]
		// keep calling crack as long as index is smaller that size
		if size-1 > index && !timedout {
			// Check pass recursive
			if breaker.crackRec(password, index+1, size, validate, timeoutChan) {
				return true
			}
			// try to validate only if are checking a full password
			// To save validate calls
		} else if index == size-1 && validate(password) && !timedout {
			return true
		}
	}
	return false
}

// crack ...
// This method iterates sequancially over all number possibilities
// in order to find the password
// Not very efficient at the moment
func (breaker *PDFBreaker) crack(
	password []byte,
	validate func([]byte) bool,
	timeoutChan chan bool) bool {

	shouldStop := breaker.shouldTimeout(timeoutChan)
	posibilities := math.Pow(float64(len(gChars)), float64(len(password)))

	// Iterate over all posibilities
	for i := 0; i < int(posibilities) && !shouldStop; i++ {
		curPosibility := i

		for j := 0; j < len(password) && !shouldStop; j++ {
			charIndex := curPosibility % len(gChars)
			password[j] = gChars[charIndex]
			curPosibility /= len(gChars)
		}

		if validate(password) {
			return true
		}

		shouldStop = breaker.shouldTimeout(timeoutChan)
	}

	return false
}

// BruteForce ...
// timeout -> timeout time in time.Duration
func (breaker *PDFBreaker) BruteForce(timeout time.Duration, isRecursive bool) ([]byte, error) {
	timeoutChan := make(chan bool)
	defer close(timeoutChan)
	timeoutDuration := time.Duration(timeout)

	if isEncrypted, _ := breaker.IsEncrypted(); !isEncrypted {
		return nil, fmt.Errorf("Cannot brute force unprotected file")
	}

	// Init password buffer
	password := make([]byte, breaker.passMaxLength)
	initPasswordSlice(password, cInitChar)

	// Validate password callback
	checkPassword := func(pass []byte) bool {
		isCorrect, _, _ := breaker.pdfReader.CheckAccessRights(pass)
		return isCorrect
	}

	start := time.Now()
	// Start timeout counter
	go func() {
		// safe send data to the channel
		defer func() {
			if recover() != nil {
				gInfo.Println("Safely recovered from channel panic")
			}
		}()

		// Wait timeoutDuration seconds
		<-time.After(timeoutDuration)
		timeoutChan <- true

	}()

	// Try crack password recursivly
	if isRecursive {
		if !breaker.crackRec(password, 0, len(password), checkPassword, timeoutChan) {
			return nil, fmt.Errorf("Failed brute forcing the password, Timeout: %t",
				breaker.isTimedout)
		}
	} else {
		if !breaker.crack(password, checkPassword, timeoutChan) {
			return nil, fmt.Errorf("Failed brute forcing the password, Timeout: %t",
				breaker.isTimedout)
		}
	}

	crackTime := time.Since(start)
	gInfo.Printf("Cracking password took %s\n", crackTime)

	_, accessRights, err := breaker.pdfReader.CheckAccessRights(password)
	if nil != err {
		fmt.Println("Failed getting access rights")
		gInfo.Println("Failed getting access rights")
	} else {
		fmt.Printf("Access rights: %v\n", accessRights)
		gInfo.Printf("Access rights: %v\n", accessRights)
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

func (breaker *PDFBreaker) GetReader() *pdf.PdfReader {
	return breaker.pdfReader
}
