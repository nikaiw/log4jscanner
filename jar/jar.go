// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package jar implements JAR scanning capabilities for log4j.
package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"

	zipfork "github.com/google/log4jscanner/third_party/zip"
	"rsc.io/binaryregexp"
)

const (
	maxZipDepth = 16
	maxZipSize  = 4 << 30 // 4GiB
)

var exts = map[string]bool{
	".jar":  true,
	".war":  true,
	".ear":  true,
	".zip":  true,
	".jmod": true,
	".par":  true,
	".kar":  true,
	".sar":  true,
}
}

// Report contains information about a scanned JAR.
type Report struct {
	// Vulnerable reports if a vulnerable version of the log4j is included in the
	// JAR and has been initialized.
	//
	// Note that this package considers the 2.15.0 versions vulnerable.
	Vulnerable bool

	// MainClass and Version are information taken from the MANIFEST.MF file.
	// Version indicates the version of JAR, NOT the log4j package.
	MainClass string
	Version   string
}

// Parse traverses a JAR file, attempting to detect any usages of vulnerable
// log4j versions.
func Parse(r *zip.Reader) (*Report, error) {
	var c checker
	if err := c.checkJAR(r, 0, 0); err != nil {
		return nil, fmt.Errorf("failed to check JAR: %v", err)
	}
	return &Report{
		Vulnerable: c.bad(),
		MainClass:  c.mainClass,
		Version:    c.version,
	}, nil
}

// ReadCloser mirrors zip.ReadCloser.
type ReadCloser struct {
	zip.Reader

	f *os.File
}

// Close closes the underlying file.
func (r *ReadCloser) Close() error {
	return r.f.Close()
}

// OpenReader mirrors zip.OpenReader, loading a JAR from a file, but supports
// self-executable JARs. See NewReader() for details.
func OpenReader(path string) (r *ReadCloser, offset int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	zr, offset, err := NewReader(f, info.Size())
	if err != nil {
		f.Close()
		return
	}
	return &ReadCloser{*zr, f}, offset, nil
}

// offsetReader is a io.ReaderAt that starts at some offset from the start of
// the file.
type offsetReader struct {
	ra     io.ReaderAt
	offset int64
}

func (o offsetReader) ReadAt(p []byte, off int64) (n int, err error) {
	return o.ra.ReadAt(p, off+o.offset)
}

// NewReader is a wrapper around zip.NewReader that supports self-executable
// JARs. JAR files with prefixed data, such as a bash script to allow them to
// run directly.
//
// If the ZIP contains a prefix, the returned offset indicates the size of the
// prefix.
//
// See:
// - https://kevinboone.me/execjava.html
// - https://github.com/golang/go/issues/10464
func NewReader(ra io.ReaderAt, size int64) (zr *zip.Reader, offset int64, err error) {
	zr, err = zip.NewReader(ra, size)
	if err == nil || !errors.Is(err, zip.ErrFormat) {
		return zr, 0, err
	}
	offset, err = zipfork.ReadZIPOffset(ra, size)
	if err != nil {
		return nil, 0, err
	}
	zr, err = zip.NewReader(offsetReader{ra, offset}, size-offset)
	return zr, offset, err
}

type checker struct {
	// Does the JAR contain the JNDI lookup class?
	hasLookupClass bool
	// Does the JAR contain JndiManager with the old constructor, a
	// version that hasn't been fixed.
	hasOldJndiManagerConstructor bool
	// Does the jar contain a string that was added in 2.16 and whether we've checked for it yet
	seenJndiManagerClass bool
	seenisJndiEnabled    bool

	mainClass string
	version   string
}

func (c *checker) done() bool {
	return c.bad() && c.mainClass != ""
}

func (c *checker) bad() bool {
	return (c.hasLookupClass && c.seenJndiManagerClass && !c.seenisJndiEnabled)
}

func walkZIP(r *zip.Reader, fn func(f *zip.File) error) error {
	for _, f := range r.File {
		if err := fn(f); err != nil {
			if errors.Is(err, fs.SkipDir) {
				return nil
			}
			return err
		}
	}
	return nil
}

const bufSize = 4 << 10 // 4 KiB

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, bufSize)
	},
}

func (c *checker) checkJAR(r *zip.Reader, depth int, size int64) error {
	if depth > maxZipDepth {
		return fmt.Errorf("reached max zip depth of %d", maxZipDepth)
	}

	err := walkZIP(r, func(zf *zip.File) error {
		d := fs.FileInfoToDirEntry(zf.FileInfo())
		p := zf.Name
		if c.done() {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}
		if strings.HasSuffix(p, ".class") {
			if c.bad() {
				// Already determined that the content is bad, no
				// need to check more.
				return nil
			}

			f, err := zf.Open()
			if err != nil {
				return fmt.Errorf("opening file %s: %v", p, err)
			}
			defer f.Close()

			info := zf.FileInfo()
			if err != nil {
				return fmt.Errorf("stat file %s: %v", p, err)
			}
			if fsize := info.Size(); fsize+size > maxZipSize {
				return fmt.Errorf("reading %s would exceed memory limit: %v", p, err)
			}
			buf := bufPool.Get().([]byte)
			defer bufPool.Put(buf)
			return c.checkClass(p, f, buf)
		}
		if p == "META-INF/MANIFEST.MF" {
			mf, err := zf.Open()
			if err != nil {
				return fmt.Errorf("opening manifest file %s: %v", p, err)
			}
			defer mf.Close()

			buf := bufPool.Get().([]byte)
			defer bufPool.Put(buf)

			s := bufio.NewScanner(mf)
			s.Buffer(buf, bufio.MaxScanTokenSize)
			for s.Scan() {
				// Use s.Bytes instead of s.Text to avoid a string allocation.
				b := s.Bytes()
				// Use IndexByte directly instead of strings.Split to avoid allocating a return slice.
				i := bytes.IndexByte(b, ':')
				if i < 0 {
					continue
				}
				k, v := b[:i], b[i+1:]
				if bytes.IndexByte(v, ':') >= 0 {
					continue
				}
				if string(k) == "Main-Class" {
					c.mainClass = strings.TrimSpace(string(v))
				} else if string(k) == "Implementation-Version" {
					c.version = strings.TrimSpace(string(v))
				}
			}
			if err := s.Err(); err != nil {
				return fmt.Errorf("scanning manifest file %s: %v", p, err)
			}
			return nil
		}

		// Scan for jars within jars.
		if !exts[path.Ext(p)] {
			return nil
		}
		// We've found a jar in a jar. Open it!
		fi, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to get archive inside of archive %s: %v", p, err)
		}
		// If we're about to read more than the max size we've configure ahead of time then stop.
		// Note that this only applies to embedded ZIPs/JARs. The outer ZIP/JAR can still be larger than the limit.
		if size+fi.Size() > maxZipSize {
			return fmt.Errorf("archive inside archive at %q is greater than 4GB, skipping", p)
		}
		f, err := zf.Open()
		if err != nil {
			return fmt.Errorf("open file %s: %v", p, err)
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read file %s: %v", p, err)
		}
		br := bytes.NewReader(data)
		r2, err := zip.NewReader(br, br.Size())
		if err != nil {
			if err == zip.ErrFormat {
				// Not a zip file.
				return nil
			}
			return fmt.Errorf("parsing file %s: %v", p, err)
		}
		if err := c.checkJAR(r2, depth+1, size+fi.Size()); err != nil {
			return fmt.Errorf("checking sub jar %s: %v", p, err)
		}
		return nil
	})
	return err
}

const (
	isJndiEnabledPattern = "isJndiEnabled"
)

var log4jPattern *binaryregexp.Regexp

func init() {
	log4jPattern = binaryregexp.MustCompile(
		fmt.Sprintf("(?P<216>%s)", isJndiEnabledPattern))
	log4jPattern.Longest()
}

func (c *checker) checkClass(filename string, r io.Reader, buf []byte) error {
	if !c.hasLookupClass && strings.Contains(filename, "JndiLookup.class") {
		c.hasLookupClass = true
	}
	checkForOldJndiManagerConstructor := !c.hasOldJndiManagerConstructor && strings.Contains(filename, "JndiManager")
	checkJndiManagerVersion := strings.Contains(filename, "JndiManager.class")
	if !checkForOldJndiManagerConstructor && !checkJndiManagerVersion {
		return nil
	}
	if checkJndiManagerVersion {
		c.seenJndiManagerClass = true
	}

	br := newByteReader(r, buf)
	matches := log4jPattern.FindReaderSubmatchIndex(br)
	// Error reading.
	if err := br.Err(); err != nil && err != io.EOF {
		return err
	}

	// No match.
	if matches == nil {
		return nil
	}

	c.seenisJndiEnabled = true
	return nil
}

type byteReader struct {
	r   io.Reader
	buf []byte
	off int
	err error
}

func newByteReader(r io.Reader, buf []byte) *byteReader {
	return &byteReader{r: r, buf: buf[:0]}
}

func (b *byteReader) ReadByte() (byte, error) {
	for b.off == len(b.buf) {
		if b.err != nil {
			return 0, b.err
		}
		n, err := b.r.Read(b.buf[:cap(b.buf)])
		b.err = err
		b.buf = b.buf[:n]
		b.off = 0
	}
	result := b.buf[b.off]
	b.off++
	return result, nil
}

func (b *byteReader) Err() error {
	return b.err
}
