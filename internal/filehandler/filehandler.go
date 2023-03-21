package filehandler

import (
	"compress/gzip"
	"io"
	"os"
)

func ExtractGz(gzipStream io.Reader) io.Reader {
	// Create a new gzip reader
	gzipReader, err := gzip.NewReader(gzipStream)
	if err != nil {
		panic(err)
	}
	defer gzipReader.Close()

	return gzipReader
}

func OpenFile(path string) *os.File {
	// Open the gzipped file
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	return file
}
