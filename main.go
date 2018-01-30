package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	b "github.com/noysh22/pdf_breaker/breaker"
	unicommon "github.com/unidoc/unidoc/common"
)

const (
	argc           = 2
	defaultTimeout = 1 * time.Minute
)

type argsT struct {
	filename      string
	passMaxLength uint
	timeout       time.Duration
}

func parseArgs() (*argsT, error) {
	const passDefaultLength = 6

	if len(os.Args) < argc {
		printUsage()
		return nil, errors.New("Not enough arguments")
	}

	args := &argsT{}

	flag.StringVar(&args.filename, "f", "", "Filename for the pdf to break")
	flag.UintVar(&args.passMaxLength, "l", passDefaultLength, "Max length for the password")
	flag.DurationVar(&args.timeout, "t", defaultTimeout, "Timeout for trying cracking the password in minutes")
	flag.Parse()

	if "" == args.filename {
		return nil, errors.New("-f is required")
	}

	return args, nil
}

func printUsage() {
	fmt.Println("====================== USAGE ======================")
	fmt.Println("pdf_breaker -f {filename} -l {passMaxLength} -t {timeout}")
	fmt.Println("========================   ========================")
}

func heapMut(arr []byte, validate func(arr []byte) bool) {
	temp := make([]byte, len(arr))

	for i := 0; i < len(arr); i++ {
		temp[i] = 0
	}

	// fmt.Println(arr)
	if validate(arr) {
		fmt.Println("Found")
		fmt.Println(arr)
	}

	i := 0
	for i < len(arr) {
		if temp[i] < byte(i) {
			if i%2 == 0 {
				arr[i], arr[0] = arr[0], arr[i]
			} else {
				arr[temp[i]], arr[i] = arr[i], arr[temp[i]]
			}

			if validate(arr) {
				fmt.Println("Found")
				fmt.Println(arr)
			}
			temp[i]++
			i = 0
		} else {
			temp[i] = 0
			i++
		}
	}
}

func main() {
	fmt.Println("PDF BREAKER")
	unicommon.SetLogger(unicommon.NewConsoleLogger(unicommon.LogLevelDebug))

	args, err := parseArgs()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("filename: %s\nmax length: %d\n", args.filename, args.passMaxLength)

	breaker, err := b.NewBreaker(args.filename, args.passMaxLength)
	if nil != err {
		fmt.Printf("Error: %v\n", err)
		return
	}

	pass, err := breaker.BruteForce(args.timeout, false)
	if nil != err {
		fmt.Printf("Error brute forcing: %v\n", err)
		return
	}

	fmt.Printf("PASSWORD CRACKED, Pass is: %s\n", pass)
	fmt.Println("Great success")

	// for i := 0; i < len(gChars); i++ {
	// 	for j := 0; j < len(arr); j++ {
	// 		arr[j] = gChars[i]
	// 		heapMut(arr, validate)
	// 	}
	// }
	// heapMut([]int{1, 3, 3}, validate)
}
