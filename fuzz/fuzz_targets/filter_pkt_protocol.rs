#![no_main]

use anyhow::{Context, Result};
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
enum PktRead {
    Data(Vec<u8>),
    Flush,
    Eof,
}

fn read_pkt_line(reader: &mut impl std::io::Read) -> Result<PktRead> {
    let mut len_buf = [0_u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(PktRead::Eof),
        Err(err) => return Err(err).context("failed reading pkt-line length"),
    }

    let len_str = std::str::from_utf8(&len_buf).context("pkt-line header is not utf8 hex")?;
    let len = usize::from_str_radix(len_str, 16).context("invalid pkt-line length")?;

    if len == 0 {
        return Ok(PktRead::Flush);
    }
    if len < 4 {
        anyhow::bail!("invalid pkt-line length < 4");
    }

    let data_len = len - 4;
    let mut data = vec![0_u8; data_len];
    reader
        .read_exact(&mut data)
        .context("failed reading pkt-line payload")?;
    Ok(PktRead::Data(data))
}

fn parse_kv(data: &[u8]) -> Result<(String, String)> {
    let text = std::str::from_utf8(data)
        .context("pkt key/value line is not utf8")?
        .trim_end_matches('\n');
    let mut split = text.splitn(2, '=');
    let key = split.next().unwrap_or_default();
    let value = split
        .next()
        .ok_or_else(|| anyhow::anyhow!("pkt key/value line missing '='"))?;
    Ok((key.to_string(), value.to_string()))
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    loop {
        let pkt = match read_pkt_line(&mut cursor) {
            Ok(pkt) => pkt,
            Err(_) => break,
        };

        match pkt {
            PktRead::Data(bytes) => {
                let _ = parse_kv(&bytes);
            }
            PktRead::Flush | PktRead::Eof => break,
        }
    }
});
