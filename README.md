# Chunker
Implementation of Tarsnap chunkifier algorithm in Go.

## Summary

Backup and synchronisation applications need an efficient way of calculating the differences between files.
A usual approach by various applications is to use some variant of
[Rabin-Karp](https://en.wikipedia.org/wiki/Rabin%E2%80%93Karp_algorithm)
rolling hash to split the incoming data stream into multiple blocks.
An example is [Rsync](https://en.wikipedia.org/wiki/Rsync) which uses a [rolling checksum algorithm](http://tutorials.jenkov.com/rsync/checksums.html).

[Tarsnap](https://en.wikipedia.org/wiki/Tarsnap) is a state-of-the-art backup
software written by Colin Percival. It uses a very efficient implementation of
the [block splitting algorithm](https://www.tarsnap.com/download/EuroBSDCon13.pdf), written in C.

This package is a re-implementation of that algorithm in Golang, ready to be
used in various Golang backup or synchronisation applications.

## Documentation
[https://godoc.org/github.com/karinushka/chunker](https://godoc.org/github.com/karinushka/chunker)

## Features
- Configurable block sizes: average and maximum chunk sizes.
- 1:1 compatibility with [original implementation in Tarsnap](https://github.com/Tarsnap/tarsnap/tree/master/tar/multitape).

## Installation

To install the package, use Golang built-in package management:

`go install "github.com/karinushka/chunker"`

Example usage is shown in `main.go` file, which reads a filename given as the
first command line parameter, splits it into variable blocks and prints a
histogram with their sizes.

