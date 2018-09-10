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

use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};

use gpgme::{Context, SignatureSummary};
use prelude::*;
use sha2::{Digest, Sha256};

pub trait Artifact<'a> {
    fn new(url: &'a str, file_path: &'a Path, attached_artifact: Option<&'a MainArtifact>) -> Self;

    fn download(&self) -> Result<usize, Error>;
}

//Store info about the location of a downloadable artifact
#[derive(Clone, Debug)]
pub struct MainArtifact<'a> {
    //The url of an artifact (like a jar or pom file)
    pub url: &'a str,
    //The local path of the downloaded artifact file
    pub file_path: &'a Path,
}

///Stores info for the location of a downloadable asc file
#[derive(Clone, Debug)]
pub struct ArtifactAsc<'a> {
    ///The url of the asc file
    pub url: &'a str,
    ///The local path of the downloaded asc file
    pub file_path: &'a Path,
    ///The artifact that asc file contains a signature for
    pub attached_artifact: &'a MainArtifact<'a>,
}

///Stores info for the location of a downloadable sha file
#[derive(Debug)]
pub struct ArtifactSha<'a> {
    ///The url of the sha file
    pub url: &'a str,
    //The local path of the downloaded sha file
    pub file_path: &'a Path,
    ///The artifact that the sha file contains a hash for
    pub attached_artifact: &'a MainArtifact<'a>,
}

#[derive(Debug)]
pub struct GpgSignature {
    pub fingerprint: String,
    pub summary: SignatureSummary,
    pub is_ok: bool,
}

#[derive(Debug)]
pub struct KeyId {
    pub id: String,
    pub url: String,
}

#[derive(Debug)]
pub struct ShaHash {
    pub hash: String,
    pub url: String,
}

#[derive(Debug)]
pub struct ArtifactInfo {
    pub sig_type: SigType,
    pub value: String,
    pub verified: bool,
}

#[derive(Debug)]
pub enum SigType {
    Sha,
    Asc,
}

impl<'a> MainArtifact<'a> {
    pub fn append_url_ext(&self, ext: &str) -> String {
        self.url.to_owned() + "." + ext
    }

    pub fn append_file_ext(&self, ext: &str) -> PathBuf {
        let a = self.file_path.to_owned();
        a.with_extension(a.extension().unwrap().to_str().unwrap().to_string() + "." + ext)
    }
}

impl<'a> ArtifactAsc<'a> {
    pub fn verify(&self, ctx: &mut Context) -> Result<GpgSignature, Error> {
        let sigfile = self.file_path.to_str().unwrap();
        let attached = self.clone().attached_artifact;
        let signed = attached.file_path.to_str().unwrap();

        let result =
            ctx.verify_detached(File::open(&sigfile).unwrap(), File::open(&signed).unwrap());
        let verification_result = result.unwrap();
        let signatures = verification_result.signatures();
        for (_i, sig) in signatures.enumerate() {
            let fingerprint = sig.fingerprint().unwrap().to_string();
            let summary = sig.summary();
            let is_ok = sig.status() == Ok(());
            return Ok(GpgSignature {
                fingerprint,
                summary,
                is_ok,
            });
        }
        Result::Err(Error::new(ErrorKind::Other, "No signatures"))
    }
}

impl<'a> ArtifactSha<'a> {
    pub fn get_hash(&self) -> Result<String, Error> {
        let file = fs::File::open(self.attached_artifact.file_path);
        let s = Sha256::digest_reader(&mut file.unwrap()).unwrap();
        Ok(format!("{:x}", s))
    }

    /// Checks if the hash contained in this file matches the hash of the attached artifact file.
    pub fn check_hash(&self) -> Result<ShaHash, Error> {
        let hash = self.get_hash().unwrap();
        let sha_check = read_file_to_string(self.file_path).unwrap();

        if sha_check == hash {
            Ok(ShaHash {
                hash,
                url: self.attached_artifact.url.to_string(),
            })
        } else {
            let message = format!(
                "Sha check mismatch {} : {} {}",
                self.attached_artifact.url, sha_check, hash
            );
            Result::Err(Error::new(ErrorKind::Other, message))
        }
    }
}

impl<'a> Artifact<'a> for MainArtifact<'a> {
    fn new(
        url: &'a str,
        file_path: &'a Path,
        _attached_artifact: Option<&'a MainArtifact>,
    ) -> MainArtifact<'a> {
        MainArtifact { url, file_path }
    }

    fn download(&self) -> Result<usize, Error> {
        download_artifact(self.url, self.file_path)
    }
}

impl<'a> Artifact<'a> for ArtifactSha<'a> {
    fn new(
        url: &'a str,
        file_path: &'a Path,
        attached_artifact: Option<&'a MainArtifact>,
    ) -> ArtifactSha<'a> {
        let attached_artifact = attached_artifact.unwrap();
        ArtifactSha {
            url,
            file_path,
            attached_artifact,
        }
    }

    fn download(&self) -> Result<usize, Error> {
        let content = download_content(self.url)?;
        if content.len() == 64 {
            fs::create_dir_all(self.file_path.parent().unwrap())?;
            return save(self.file_path, content.as_slice());
        }
        Err(Error::new(
            ErrorKind::Other,
            format!("[{}] Sha artifact found but incorrect size", self.url),
        ))
    }
}

impl<'a> Artifact<'a> for ArtifactAsc<'a> {
    fn new(
        url: &'a str,
        file_path: &'a Path,
        attached_artifact: Option<&'a MainArtifact>,
    ) -> ArtifactAsc<'a> {
        let attached_artifact = attached_artifact.unwrap();
        ArtifactAsc {
            url,
            file_path,
            attached_artifact,
        }
    }

    fn download(&self) -> Result<usize, Error> {
        download_artifact(self.url, self.file_path)
    }
}
