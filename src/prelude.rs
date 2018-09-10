// Shane Isbell licenses this file to you under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License. See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufReader, Error, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::result::Result::Err;

use artifacts::*;
use gpgme::{Context, Data, SignatureSummary};
use reqwest::{self, StatusCode, Url};
use sha2::{Digest, Sha256};

pub fn artifact_not_found(url: &str) -> Error {
    Error::new(ErrorKind::Other, format!("[{}] Artifact not found", url))
}

pub fn create_file(path: &PathBuf, filename: &str) -> Result<File, Error> {
    let x = PathBuf::new().join(&path).join(filename);
    File::create(x)
}

pub fn default_artc_dir() -> PathBuf {
    PathBuf::new().join("target").join("artc")
}

pub fn default_artifacts_dir() -> PathBuf {
    default_artc_dir().join("artifacts")
}

pub fn default_keyring() -> PathBuf {
    default_artc_dir().join("pubring.kbx")
}

pub fn default_keys_dir() -> PathBuf {
    default_artc_dir().join("keys")
}

pub fn default_rbm_dir() -> PathBuf {
    default_artc_dir().join("rbm")
}

pub fn default_maven_repo_dir() -> PathBuf {
    default_artc_dir().join("m2")
}

pub fn download_artifact(url: &str, file_path: &Path) -> Result<usize, Error> {
    fs::create_dir_all(file_path.parent().unwrap());
    save(file_path, download_content(url)?.as_slice())
}

pub fn download_content(url: &str) -> io::Result<Vec<u8>> {
    println!("Downloading {}", url);
    match reqwest::get(url) {
        Result::Ok(mut r) => match r.status() {
            StatusCode::Ok => {
                let mut buf: Vec<u8> = vec![];
                r.copy_to(&mut buf);
                Ok(buf)
            }
            _s => Err(artifact_not_found(url)),
        },
        Result::Err(_err) => Err(artifact_not_found(url)),
    }
}

pub fn download_key(key_id: &String, file_path: &Path) -> Result<usize, Error> {
    //  fs::create_dir_all(file_path.parent().unwrap());
    let url = format!(
        "https://pgp.mit.edu/pks/lookup?op=get&search=0x{}&options=mr",
        key_id
    );
    save(file_path, download_content(url.as_str())?.as_slice())
}

pub fn get_buffer(filename: &str) -> io::Result<BufReader<File>> {
    Ok(BufReader::new(File::open(filename)?))
}

pub fn get_buffer_from_file(file: File) -> io::Result<BufReader<File>> {
    Ok(BufReader::new(file))
}

pub fn get_filename_from_url(url: &str, download_dir: &Path) -> Result<PathBuf, Error> {
    let url = Url::parse(url).unwrap();

    let mut path = PathBuf::new().join(download_dir);
    for p in tokenize_url_path(url.path()) {
        path.push(p);
    }
    Ok(path)
}

pub fn get_hash(file: &Path) -> Result<String, Error> {
    let file = fs::File::open(file);
    let s = Sha256::digest_reader(&mut file.unwrap()).unwrap();
    Ok(format!("{:x}", s))
}

pub fn import_to_keystore(path: &Path, ctx: &mut Context) {
    let input = File::open(path).unwrap();
    let mut data = Data::from_seekable_stream(input).unwrap();
    ctx.import(&mut data).unwrap();
    //   print_import_result(ctx.import(&mut data).unwrap());
}

pub fn log(line: String, mut file: &File) {
    let content = format!("{}\r\n", line);
    file.write_all(content.as_bytes());
}

pub fn merge(
    map1: HashMap<String, ArtifactInfo>,
    map2: HashMap<String, ArtifactInfo>,
) -> HashMap<String, ArtifactInfo> {
    map1.into_iter().chain(map2).collect()
}

pub fn open_file(path: &PathBuf, filename: &str) -> Result<File, Error> {
    let x = PathBuf::new().join(&path).join(filename);
    File::open(x)
}

pub fn read_file_to_string(file: &Path) -> Result<String, Error> {
    let mut file = File::open(file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents);
    Ok(contents)
}

pub fn save(filename: &Path, content: &[u8]) -> Result<usize, Error> {
    let mut file = File::create(filename)?;
    file.write(content)
}

pub fn split_by_tab(line: String) -> Vec<String> {
    let x: Vec<&str> = line.split("\t").collect();
    x.iter().map(|s| s.to_string()).collect()
}

pub fn tab_fmt2<'a>(field1: String, field2: String, mut file: &File) {
    let content = format!("{} \t {}\r\n", field1, field2);
    file.write_all(content.as_bytes());
}

pub fn tab_fmt3<'a>(field1: String, field2: String, field3: String, mut file: &File) {
    let content = format!("{} \t {} \t {}\r\n", field1, field2, field3);
    file.write_all(content.as_bytes());
}

fn tokenize_url_path(url: &str) -> Vec<&str> {
    url.split("/").collect()
}

pub fn verify_artifact(
    asc_artifact: &ArtifactAsc,
    keys_dir: &PathBuf,
    gpg_context: &mut Context,
) -> Result<KeyId, Error> {
    let sig = asc_artifact.verify(gpg_context)?;
    if sig.is_ok {
        Ok(KeyId {
            id: sig.fingerprint,
            url: asc_artifact.attached_artifact.url.to_string(),
        })
    } else {
        match sig.summary {
            SignatureSummary::KEY_MISSING => {
                let key_id = sig.fingerprint;
                let z = keys_dir.clone().join(&key_id);
                let file_path = z.as_path();

                println!("Missing key: {} ", key_id.as_str());
                download_key(&key_id, file_path)?;
                import_to_keystore(file_path.clone(), gpg_context);

                let sig = asc_artifact.verify(gpg_context)?;
                if sig.is_ok {
                    Ok(KeyId {
                        id: sig.fingerprint,
                        url: asc_artifact.attached_artifact.url.to_string(),
                    })
                } else {
                    Result::Err(Error::new(ErrorKind::Other, "Signature does not match"))
                }
            }
            _ => Result::Err(Error::new(ErrorKind::Other, "Signature invalid")),
        }
    }
    //handle other cases
}
