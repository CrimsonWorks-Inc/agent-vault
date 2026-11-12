//! Response decompression before scrubbing. Ports `decompress` and
//! `decompressStream` in `src/daemon/pipeline.js`.
//!
//! A compressed body is an amplifier, so every decoder here is capped at
//! [`MAX_DECOMPRESSED`] bytes of output, counted over the whole body (or the
//! whole stream), and refuses past it. `zstd` is refused exactly as Node 20
//! refuses it: the reference daemon runs on a Node build without it.

use std::io::{self, Read, Write};

use crate::pipeline::MAX_DECOMPRESSED;

/// Why a body could not be decoded. The message is never shown to the
/// agent; the pipeline answers with its own sentence.
#[derive(Debug)]
pub struct DecodeError(pub String);

/// `decompress(buf, encoding)`: the whole body, capped.
pub fn decompress(buf: &[u8], encoding: &str) -> Result<Vec<u8>, DecodeError> {
    decompress_capped(buf, encoding, MAX_DECOMPRESSED)
}

/// [`decompress`] with an explicit cap (tests drive the bound with a small one).
pub fn decompress_capped(buf: &[u8], encoding: &str, cap: usize) -> Result<Vec<u8>, DecodeError> {
    let reader: Box<dyn Read + '_> = match encoding {
        "gzip" | "x-gzip" => Box::new(flate2::read::MultiGzDecoder::new(buf)),
        "deflate" => Box::new(flate2::read::ZlibDecoder::new(buf)),
        "br" => Box::new(brotli_decompressor::Decompressor::new(buf, 4096)),
        "zstd" => {
            return Err(DecodeError(
                "zstd is not supported by this Node build".into(),
            ))
        }
        other => return Err(DecodeError(format!("unknown content-encoding {other}"))),
    };
    read_capped(reader, cap)
}

fn read_capped(reader: impl Read, cap: usize) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    // One byte past the cap is enough to know it was exceeded.
    let mut limited = reader.take(cap as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| DecodeError(e.to_string()))?;
    if out.len() > cap {
        return Err(DecodeError(
            "Cannot create a Buffer larger than maxOutputLength".into(),
        ));
    }
    Ok(out)
}

/// `decompressStream(encoding)`: an incremental decoder, or `None` for an
/// encoding that cannot be read (zstd included). Each `push` returns what
/// the new bytes decoded to; past `cap` total it fails.
pub fn stream_decoder(encoding: &str) -> Option<StreamDecoder> {
    StreamDecoder::new(encoding, MAX_DECOMPRESSED)
}

/// An incremental, capped decoder.
pub struct StreamDecoder {
    inner: Inner,
    cap: usize,
    total: usize,
}

enum Inner {
    Gzip(flate2::write::MultiGzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Vec<u8>>>),
}

impl StreamDecoder {
    /// A decoder for `encoding` with output capped at `cap`.
    pub fn new(encoding: &str, cap: usize) -> Option<StreamDecoder> {
        let inner = match encoding {
            "gzip" | "x-gzip" => Inner::Gzip(flate2::write::MultiGzDecoder::new(Vec::new())),
            "deflate" => Inner::Deflate(flate2::write::ZlibDecoder::new(Vec::new())),
            "br" => Inner::Brotli(Box::new(brotli_decompressor::DecompressorWriter::new(
                Vec::new(),
                4096,
            ))),
            _ => return None,
        };
        Some(StreamDecoder {
            inner,
            cap,
            total: 0,
        })
    }

    fn take(&mut self) -> Vec<u8> {
        match &mut self.inner {
            Inner::Gzip(w) => std::mem::take(w.get_mut()),
            Inner::Deflate(w) => std::mem::take(w.get_mut()),
            Inner::Brotli(w) => std::mem::take(w.get_mut()),
        }
    }

    /// Feed compressed bytes; returns what they decoded to.
    pub fn push(&mut self, chunk: &[u8]) -> io::Result<Vec<u8>> {
        // Written a slice at a time so no single write can expand past the
        // cap before it is counted.
        let mut out = Vec::new();
        for piece in chunk.chunks(1024) {
            match &mut self.inner {
                Inner::Gzip(w) => w.write_all(piece)?,
                Inner::Deflate(w) => w.write_all(piece)?,
                Inner::Brotli(w) => w.write_all(piece)?,
            }
            let got = self.take();
            self.total += got.len();
            out.extend_from_slice(&got);
            if self.total > self.cap {
                return Err(io::Error::other("decoded stream exceeded its bound"));
            }
        }
        Ok(out)
    }

    /// The end of the compressed stream.
    pub fn finish(&mut self) -> io::Result<Vec<u8>> {
        match &mut self.inner {
            Inner::Gzip(w) => w.try_finish()?,
            Inner::Deflate(w) => w.try_finish()?,
            Inner::Brotli(w) => w.flush()?,
        }
        let got = self.take();
        self.total += got.len();
        if self.total > self.cap {
            return Err(io::Error::other("decoded stream exceeded its bound"));
        }
        Ok(got)
    }

    /// Bytes decoded so far.
    pub fn total(&self) -> usize {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    // A small, very high-ratio gzip body is refused past the bound; an
    // ordinary one decodes.
    #[test]
    fn hardening_gzip_bomb_is_refused_and_ordinary_body_decodes() {
        let bomb = gzip(&vec![b'a'; 4 * 1024 * 1024]);
        assert!(bomb.len() < 16 * 1024, "the bomb is small: {}", bomb.len());
        assert!(decompress_capped(&bomb, "gzip", 1024 * 1024).is_err());
        let ok = gzip(b"{\"ok\":true}");
        assert_eq!(
            decompress_capped(&ok, "gzip", 1024 * 1024).unwrap(),
            b"{\"ok\":true}"
        );
    }

    #[test]
    fn hardening_streamed_bomb_is_cut_over_the_whole_stream() {
        let bomb = gzip(&vec![b'a'; 4 * 1024 * 1024]);
        let mut d = StreamDecoder::new("gzip", 1024 * 1024).unwrap();
        let mut failed = false;
        for c in bomb.chunks(512) {
            if d.push(c).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        let ok = gzip(b"data: hi\n\n");
        let mut d = StreamDecoder::new("gzip", 1024).unwrap();
        let mut out = d.push(&ok).unwrap();
        out.extend(d.finish().unwrap());
        assert_eq!(out, b"data: hi\n\n");
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Made with Node's zlib.brotliCompressSync: 4 MiB of 'a' in 14 bytes, and
    // the body {"ok":true}.
    #[test]
    fn hardening_brotli_bomb_is_refused_and_ordinary_body_decodes() {
        let bomb = unhex("9bffff3ff825c2e2b14020f7fe07");
        assert!(decompress_capped(&bomb, "br", 1024 * 1024).is_err());
        assert_eq!(
            decompress_capped(&bomb, "br", 8 * 1024 * 1024)
                .unwrap()
                .len(),
            4 * 1024 * 1024
        );
        let ok = unhex("0b05807b226f6b223a747275657d03");
        assert_eq!(decompress(&ok, "br").unwrap(), b"{\"ok\":true}");
        let mut d = StreamDecoder::new("br", 1024 * 1024).unwrap();
        let mut failed = false;
        for c in bomb.chunks(3) {
            if d.push(c).is_err() {
                failed = true;
            }
        }
        assert!(failed || d.finish().is_err());
    }

    #[test]
    fn zstd_and_unknown_encodings_are_refused() {
        assert_eq!(
            decompress(b"x", "zstd").unwrap_err().0,
            "zstd is not supported by this Node build"
        );
        assert!(stream_decoder("zstd").is_none());
        assert!(decompress(b"x", "compress").is_err());
    }
}
