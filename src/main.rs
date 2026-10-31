#![forbid(unsafe_code)]
use anyhow::{anyhow, ensure, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use robot_cyber_shield::{Claims, Grant, Guard, Policy, Request, MAX_INPUT_BYTES};
use std::{
    fs::{self, File},
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Parser)]
#[command(
    version,
    about = "Signed robot command authorization and minimal operational telemetry"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Issue {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        claims: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    SignRequest {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        grant: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Serve {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    Audit {
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    Revoke {
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        grant_id: String,
    },
}
fn read(path: &Path, limit: usize, secret: bool) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_file(),
        "Expected regular non-symlink file"
    );
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "Private key must have private permissions"
        );
    }
    #[cfg(not(unix))]
    let _ = secret;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "File exceeds input budget");
    Ok(bytes)
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn private(path: &Path) -> Result<SigningKey> {
    let raw = read(path, 128, true)?;
    let raw = std::str::from_utf8(&raw)
        .map_err(|_| anyhow!("Invalid private key"))?
        .trim();
    let bytes: [u8; 32] = hex::decode(raw)
        .map_err(|_| anyhow!("Invalid private key"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid private key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
fn decode<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read(path, MAX_INPUT_BYTES, false)?)
        .map_err(|_| anyhow!("Invalid JSON schema"))
}
fn save<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(value)?;
    b.push(b'\n');
    write(path, &b)
}
fn main() -> Result<()> {
    match Args::parse().command {
        Command::Audit { state, limit } => println!(
            "{}",
            serde_json::to_string(&robot_cyber_shield::audit(&state, limit)?)?
        ),
        Command::Keygen {
            private_key,
            public_key,
        } => {
            ensure!(
                !private_key.exists() && !public_key.exists() && private_key != public_key,
                "Key output must be new distinct files"
            );
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|_| anyhow!("Operating-system random source failed"))?;
            let key = SigningKey::from_bytes(&seed);
            write(
                &private_key,
                format!("{}\n", hex::encode(key.to_bytes())).as_bytes(),
            )?;
            write(
                &public_key,
                format!("{}\n", hex::encode(key.verifying_key().to_bytes())).as_bytes(),
            )?;
            println!("{{\"created\":true}}");
        }
        Command::Issue {
            private_key,
            claims,
            output,
        } => save(
            &output,
            &robot_cyber_shield::issue(decode::<Claims>(&claims)?, &private(&private_key)?)?,
        )?,
        Command::SignRequest {
            private_key,
            grant,
            request,
            output,
        } => save(
            &output,
            &robot_cyber_shield::sign_request(
                decode::<Grant>(&grant)?,
                decode::<Request>(&request)?,
                &private(&private_key)?,
            )?,
        )?,
        Command::Revoke { state, grant_id } => {
            robot_cyber_shield::revoke(&state, &grant_id)?;
            println!("{{\"revoked\":true}}");
        }
        Command::Serve {
            state,
            policy,
            public_key,
        } => {
            let key = read(&public_key, 128, false)?;
            let key = std::str::from_utf8(&key)
                .map_err(|_| anyhow!("Invalid public key"))?
                .trim();
            let mut guard = Guard::open(
                &state,
                decode::<Policy>(&policy)?,
                robot_cyber_shield::public_key(key)?,
            )?;
            let stdin = std::io::stdin();
            let mut input = stdin.lock();
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            loop {
                let mut line = Vec::new();
                let read = (&mut input)
                    .take(MAX_INPUT_BYTES as u64 + 2)
                    .read_until(b'\n', &mut line)?;
                if read == 0 {
                    break;
                }
                let oversized = line.len() > MAX_INPUT_BYTES + 1
                    || (line.len() == MAX_INPUT_BYTES + 1 && line.last() != Some(&b'\n'));
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
                let now = u64::try_from(now).map_err(|_| anyhow!("Clock exceeds range"))?;
                let decision = if oversized {
                    guard.process(&line, now)
                } else {
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    guard.process(&line, now)
                };
                serde_json::to_writer(&mut out, &decision)?;
                out.write_all(b"\n")?;
                out.flush()?;
                // Stop instead of processing a suffix of an oversized frame.
                if oversized {
                    break;
                }
            }
        }
    }
    Ok(())
}
