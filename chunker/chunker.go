package chunker

//
// Re-implementation of Chunkify algorithm from Tarsnap.
//
// Original implementation by by Colin Percival.
// https://github.com/Tarsnap/tarsnap/tree/master/tar/multitape
//
// Design: https://www.tarsnap.com/download/EuroBSDCon13.pdf
//

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// Maximum chunk size.
// This is chosen so that after deflating (which might add up to 0.1% + 13
// bytes to the size) and adding cryptographic wrapping (which will add 296
// bytes) the final maximum file size is <= 2^18.
const MAXCHUNK = 261120
const MEANCHUNK = 65536

// Minimum substring length; size of b[]
const W = 32

type Callback func([]byte) error

type Chunker struct {
	// /* Chunkification parameters */
	// uint32_t mu;		/* Desired mean chunk length */
	// uint32_t p;		/* Modulus */
	// uint32_t pp;		/* - p^(-1) mod 2^32 */
	// uint32_t ar;		/* alpha * 2^32 mod p */
	// uint32_t * cm;		/* Coefficient map modulo p */
	// uint32_t htlen;		/* Size of hash table in 2-word entries */
	// uint32_t blen;		/* Length of buf[] */
	// uint32_t w;		/* Minimum substring length; size of b[] */
	//
	// /* Callback parameters */
	// chunkify_callback * chunkdone;	/* Callback */
	// void * cookie;		/* Cookie passed to callback */
	//
	// /* Current state */
	// uint32_t k;		/* Number of bytes in chunk so far */
	// uint32_t r;		/* floor(sqrt(4 * k - mu)) */
	// uint32_t rs;		/* (r + 1)^2 - (4 * k - mu) */
	// uint32_t akr;		/* a^k * 2^32 mod p */
	// uint32_t yka;		/* Power series truncated before x^k term */
	// 			/* evaluated at a mod p */
	// uint32_t * b;		/* Circular buffer of values waiting to */
	// 			/* be added to the hash table. */
	// uint32_t * ht;		/* Hash table; pairs of the form (yka, k). */
	// uint8_t * buf;		/* Buffer of bytes processed */

	// Chunkification parameters
	mu    uint32   // Desired mean chunk length
	p     uint32   // Modulus
	pp    uint32   // - p^(-1) mod 2^32
	ar    uint32   // alpha * 2^32 mod p
	cm    []uint32 // Coefficient map modulo p
	htlen uint32   // Size of hash table in 2-word entries
	blen  uint32   // Length of buffer

	// Current state
	k   uint32   // Number of bytes in chunk so far
	r   uint32   // floor(sqrt(4 * k - mu))
	rs  uint32   // (r + 1)^2 - (4 * k - mu)
	akr uint32   //  a^k * 2^32 mod p
	yka uint32   // Power series truncated before x^k term. Evaluated at a mod p
	b   []uint32 // Circular buffer of values waiting to be added to the hash table.
	ht  []uint32 // Hash table; pairs of the form (yka, k).
	buf []byte   // Buffer of bytes processed

	Callback Callback
}

// Return nonzero iff n is prime.
func isPrime(n uint32) bool {
	for x := uint32(2); (x*x <= n) && (x < 65536); x++ {
		if n%x == 0 {
			return false
		}
	}
	return (n > 1)
}

// Return the smallest prime satisfying n <= p < 2^32, or 0 if none exist.
func nextPrime(n uint32) uint32 {
	var p uint32
	for p = n; p != 0; p++ {
		if isPrime(p) {
			break
		}
	}
	return p
}

// Compute $(a * b + (a * b * pp \bmod 2^{32}) * p) / 2^{32}$.
// Note that for $b \leq p$ this is at most $p * (1 + a / 2^{32})$.
func mMul(a, b, p, pp uint32) uint32 {
	ab := uint64(a) * uint64(b)
	abpp := uint32(ab) * pp
	ab += uint64(abpp) * uint64(p)
	return uint32(ab >> 32)
}

// Return nonzero if (ar / 2^32) has multiplicative order at least ord mod p.
func minOrder(ar, ord, p, pp uint32) bool {
	akr := (-p) % p
	akr0 := akr

	for k := uint32(0); k < ord; k++ {
		akr = mMul(akr, ar, p, pp) % p
		if akr == akr0 {
			return false
		}
	}

	return true
}

func generateHmac(key, data []byte) uint32 {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return binary.LittleEndian.Uint32(mac.Sum(nil))
}

//
// Prepare the Chunkifier for input.
//
func (c *Chunker) Start() {
	// No entries in the hash table.
	for i := 0; i < len(c.ht); i++ {
		c.ht[i] = -c.htlen
	}

	// Nothing in the queue waiting to be added to the table, either.
	for i := 0; i < len(c.b); i++ {
		c.b[i] = c.p
	}

	// No bytes input yet.
	c.akr = (-c.p) % c.p
	c.yka = 0
	c.buf = c.buf[:0]
	c.r = 0
	c.rs = 1 + c.mu
}

func (c *Chunker) Write(in []byte) error {
	var yka_tmp, htpos uint32

	for i := 0; i < len(in); i++ {
		// Add byte to buffer.
		c.buf = append(c.buf, in[i])

		for c.rs <= 4 {
			c.rs += 2*c.r + 1
			c.r += 1
		}
		c.rs -= 4

		if uint32(len(c.buf)) == c.blen {
			// If k = blen, then we've filled the buffer and we
			// automatically have the end of the chunk.
			goto endofchunk
		}

		if c.r == 0 {
			// Don't waste time on arithmetic if we don't have enough
			// data yet for a permitted loop to ever occur.
			continue
		}

		// Update state to add new character.

		// y_k(a) := y_k(a) + a^k * x_k mod p
		// yka <= p * (2 + p / (2^32 - p)) <= p * 2.5 < 2^31 + p
		c.yka += mMul(c.akr, c.cm[in[i]], c.p, c.pp)

		// Each step reduces yka by p iff yka >= p.
		c.yka -= c.p & (((c.yka - c.p) >> 31) - 1)
		c.yka -= c.p & (((c.yka - c.p) >> 31) - 1)

		// a^k := a^k * alpha mod p
		// akr <= p * 2^32 / (2^32 - p)
		c.akr = mMul(c.akr, c.ar, c.p, c.pp)

		// Check if yka is in the hash table.
		htpos = c.yka & (c.htlen - 1)
		for {
			// Have we found yka?
			if c.ht[2*htpos+1] == c.yka {
				// Recent enough to be a valid entry?
				if uint32(len(c.buf))-c.ht[2*htpos]-1 < c.r {
					goto endofchunk
				}
			}

			// Have we found an empty space?
			if uint32(len(c.buf))-c.ht[2*htpos]-1 >= 2*c.r {
				break
			}

			// Move to the next position in the table.
			htpos = (htpos + 1) & (c.htlen - 1)
		}

		// Insert queued value into table.
		yka_tmp = c.b[uint32(len(c.buf))&(W-1)]
		htpos = yka_tmp & (c.htlen - 1)
		for {
			// Have we found an empty space or tombstone?
			if uint32(len(c.buf))-c.ht[2*htpos]-1 >= c.r {
				c.ht[2*htpos] = uint32(len(c.buf))
				c.ht[2*htpos+1] = yka_tmp
				break
			}

			// Move to the next position in the table.
			htpos = (htpos + 1) & (c.htlen - 1)
		}

		// Add current value into queue.
		c.b[uint32(len(c.buf))&(W-1)] = c.yka

		// Move on to next byte.
		continue

	endofchunk:
		// We've reached the end of a chunk.
		if err := c.End(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Chunker) End() error {
	// If we haven't started the chunk yet, don't end it either.
	if len(c.buf) == 0 {
		return nil
	}

	// Process the chunk.
	if err := c.Callback(c.buf); err != nil {
		return err
	}

	// Prepare for more input.
	c.Start()
	return nil
}

func ChunkifyInit(key []byte, mean, max uint32, cb Callback) (*Chunker, error) {
	if mean > 1262226 || max <= mean {
		return nil, fmt.Errorf("Incorrect API usage")
	}

	c := &Chunker{
		mu:       mean,
		blen:     max,
		Callback: cb,
	}

	//
	// Compute the necessary hash table size. At any given time, there are
	// sqrt(4 k - mu) entries and up to sqrt(4 k - mu) tombstones in the hash
	// table, and we want table inserts and lookups to be fast, so we want
	// these to use up no more than 50% of the table.  We also want the table
	// size to be a power of 2.
	//
	// Consequently, the table size should be the least power of 2 in excess of
	// 4 * sqrt(4 maxlen - mu) = 8 * sqrt(maxlen - mu / 4).
	//
	c.htlen = 8
	for i := c.blen - c.mu/4; i > 0; i >>= 2 {
		c.htlen <<= 1
	}

	c.cm = make([]uint32, 256)
	c.b = make([]uint32, W)
	c.ht = make([]uint32, 2*c.htlen)
	c.buf = make([]byte, 0, max)

	// Generate parameter values by computing HMACs.

	// p is generated from HMAC('p\0').
	c.p = generateHmac(key, []byte{'p', 0})

	/* alpha is generated from HMAC('a\0'). */
	c.ar = generateHmac(key, []byte{'a', 0})

	/* cm[i] is generated from HMAC('x' . i). */
	b := []byte{'x', 0}
	for i := 0; i < 256; i++ {
		b[1] = byte(i) & 0xff
		c.cm[i] = generateHmac(key, b)
	}

	//
	// Using the generated pseudorandom values, actually generate
	// the parameters we want.
	//

	//
	// We want p to be approximately mu^(3/2) * 1.009677744.
	// Compute p to be at least floor(mu*floor(sqrt(mu))*1.01) and no more than
	// floor(sqrt(mu)) - 1 more than that.
	//
	pmin := c.mu * uint32(math.Sqrt(float64(c.mu)))
	pmin += pmin / 100
	c.p = nextPrime(pmin + (c.p % uint32(math.Sqrt(float64(c.mu)))))
	// c->p <= 1431655739 < 1431655765 = floor(2^32 / 3)

	// Compute pp = - p^(-1) mod 2^32.
	c.pp = ((2*c.p + 4) & 8) - c.p // pp = - 1/p mod 2^4
	c.pp *= 2 + c.p*c.pp           // pp = - 1/p mod 2^8
	c.pp *= 2 + c.p*c.pp           // pp = - 1/p mod 2^16
	c.pp *= 2 + c.p*c.pp           // pp = - 1/p mod 2^32

	//
	// We want to have 1 < ar < p - 1 and the multiplicative order of alpha mod
	// p greater than mu.
	//
	c.ar = 2 + (c.ar % (c.p - 3))
	for !minOrder(c.ar, c.mu, c.p, c.pp) {
		c.ar += 1
		if c.ar == c.p {
			c.ar = 2
		}
	}

	//
	// Prepare for incoming data.
	//
	c.Start()

	return c, nil
}
