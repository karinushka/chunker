package main

import (
	"github.com/karinushka/chunker/chunker"

	"fmt"
	"io/ioutil"
	"os"

	"github.com/aybabtme/uniplot/histogram"
)

var chunks []float64

func chunkDone(buf []byte) error {
	chunks = append(chunks, float64(len(buf))/chunker.MAXCHUNK)
	return nil
}

func labelFormat(v float64) string {
	return fmt.Sprintf("%vkb", uint(v*chunker.MAXCHUNK/1024))
}

func main() {
	f, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	key := []byte("12345678901234567890123456789012")
	c, _ := chunker.ChunkifyInit(key, chunker.MEANCHUNK, chunker.MAXCHUNK, chunkDone)
	c.Write(f)
	c.End()

	buckets := chunker.MAXCHUNK / 1024 / 4
	h1 := histogram.Hist(buckets, chunks)
	histogram.Fprintf(os.Stdout, h1, histogram.Linear(60), labelFormat)
}
