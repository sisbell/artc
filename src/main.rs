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

extern crate artc;
extern crate clap;
extern crate cstr_argument;
extern crate flate2;
extern crate gpgme;
extern crate reqwest;
extern crate tar;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, Error, Write};
use std::path::{Path, PathBuf};
use std::result::Result;

use artc::artifacts::*;
use artc::prelude::*;
use clap::{App, Arg, SubCommand};
use cstr_argument::CStrArgument;
use flate2::write::GzEncoder;
use flate2::Compression;
use gpgme::Context as GpgContext;
use gpgme::Protocol;
use tar::Builder;

fn main() -> Result<(), Error> {
    let artc_dir = default_artc_dir();
    fs::create_dir_all(&artc_dir)?;

    //artc download --input {file_name}
    //artc rbm --keyring {name}
    //artc package

    let matches = App::new("artc")
        .version("0.1.0")
        .author("Shane Isbell <shane.isbell@gmail.com>")
        .about("Program for downloading artifacts and verifying the sha hashes and pgp signatures.")
        .subcommand(
            SubCommand::with_name("download")
                .about(
                    "Downloads artifacts, verifies hashes/configs and imports keys into keystore",
                )
                .arg(
                    Arg::with_name("input")
                        .help("input file containing URLs of artifacts")
                        .takes_value(true)
                        .short("i")
                        .long("input"),
                ),
        )
        .subcommand(
            SubCommand::with_name("rbm")
                .about("generates tor rbm config file for downloads")
                .arg(
                    Arg::with_name("keyring")
                        .help("the keyring name to use in generated config files")
                        .takes_value(true)
                        .short("k")
                        .long("keyring"),
                ),
        )
        .subcommand(
            SubCommand::with_name("package")
                .about("Packages artifacts into a maven repo and archives repo into single file"),
        )
        .get_matches();

    let command = match matches.subcommand_name() {
        Some("download") => Command::DownloadArtifacts,
        Some("rbm") => Command::RbmConfigs,
        Some("package") => Command::PackageArtifacts,
        _ => Command::NoCommand,
    };

    match command {
        Command::DownloadArtifacts => {
            let input_file = matches
                .subcommand_matches("download")
                .unwrap()
                .value_of("input")
                .unwrap();

            let mut log_file = create_file(&artc_dir, "download.log").unwrap();
            let mut sha_file = create_file(&artc_dir, "sha.tsv").unwrap();
            let mut asc_file = create_file(&artc_dir, "asc.tsv").unwrap();

            let reader = get_buffer(input_file).unwrap();
            let download_dir = default_artifacts_dir();
            let pgp_keys_dir = default_keys_dir();

            match fs::create_dir_all(&pgp_keys_dir) {
                Ok(()) => {
                    for line_result in reader.lines() {
                        //.filter(|line| !line.unwrap().is_empty()) {
                        match line_result {
                            Result::Ok(url) => manage_artifact_downloads(
                                url,
                                &download_dir,
                                &pgp_keys_dir,
                                &log_file,
                                &sha_file,
                                &asc_file,
                            ),
                            Result::Err(err) => {
                                log_file.write_fmt(format_args!(
                                    "Unable to download artifact: {}",
                                    err.to_string()
                                ))?;
                            }
                        }
                    }
                }
                Err(e) => {
                    log(e.to_string(), &log_file);
                }
            }
            //cp keyring
        }
        Command::RbmConfigs => {
            let rbm_dir = default_rbm_dir();
            fs::create_dir_all(&rbm_dir)?;

            let mut rbm_file = create_file(&rbm_dir, "config").unwrap();
            let mut repo_file = create_file(&rbm_dir, "create_maven_repo.sh").unwrap();

            let keyring = matches
                .subcommand_matches("rbm")
                .unwrap()
                .value_of("keyring")
                .unwrap();

            match fs::copy(default_keyring(), PathBuf::new().join(default_artc_dir()).join(keyring)) {
                Ok(_) =>  println!("Copied keyring {}", keyring),
                Err(_) => { println!("Failed to copy keyring {}", keyring)}
            }

            let artifact_map = collect_artifacts(&artc_dir);

            //config
            for (url, artifact_info) in &artifact_map {
                match artifact_info.sig_type {
                    SigType::Asc => {
                        let out = format!("  - URL: {}\r\n    sig_ext: asc\r\n    file_gpg_id: {}\r\n    gpg_keyring: {}\r\n", &url, &artifact_info.value, keyring);
                        rbm_file.write_all(out.as_bytes())?;
                    }
                    SigType::Sha => {
                        let out = format!(
                            "  - URL: {}\r\n    sha256Sum: {}\r\n",
                            &url, &artifact_info.value
                        );
                        if !artifact_info.verified {
                            rbm_file.write_all(
                                "    #Sha not verified from original source\r\n".as_bytes(),
                            )?;
                        }
                        rbm_file.write_all(out.as_bytes())?;
                    }
                }
            }

            println!("Wrote rbm config to {:?}", rbm_file);

            repo_file
                .write_all("# TODO: Set $M2_REPO to location of maven repository\r\n".as_bytes())?;
            for (url, _artifact_info) in &artifact_map {
                let filename = get_filename_from_url(&url, Path::new("/")).unwrap();
                let out = format!(
                    "mkdir -p $M2_REPO{} && cp {:?} \"$_\"\r\n",
                    filename.parent().unwrap().to_str().unwrap(),
                    filename.file_name().unwrap()
                );
                repo_file.write_all(out.as_bytes())?;
            }
            println!("Wrote maven repo script to {:?}", repo_file);
        }
        Command::PackageArtifacts => {
            let artifact_map = collect_artifacts(&artc_dir);
            let base_dir = default_artifacts_dir();
            for (url, _artifact_info) in &artifact_map {
                let src_filename = get_filename_from_url(&url, &base_dir).unwrap();
                let x = get_filename_from_url(&url, Path::new("")).unwrap();

                let target_filename = default_maven_repo_dir().join(x);
                fs::create_dir_all(&target_filename.parent().unwrap())?;
                match fs::copy(&src_filename, &target_filename) {
                    Ok(_) => println!("Copied file: {:?}", target_filename),
                    Err(e) => {
                        println!("{} {:?} {:?}", e.to_string(), src_filename, target_filename)
                    }
                }
            }

            let archive_path = PathBuf::new().join(&artc_dir).join("maven-repo.tar.gz");
            let tar_gz = File::create(&archive_path).unwrap();
            let enc = GzEncoder::new(&tar_gz, Compression::default());
            let mut tar = Builder::new(enc);
            tar.append_dir_all("m2", default_maven_repo_dir())?;
            println!(
                "Created archive {} with hash: {}",
                &archive_path.display(),
                get_hash(archive_path.as_path()).unwrap()
            );
        }

        Command::NoCommand => {}
    }
    Ok(())
}

fn collect_artifacts(artc_dir: &PathBuf) -> HashMap<String, ArtifactInfo> {
    let sha_file = open_file(&artc_dir, "sha.tsv").unwrap();
    let asc_file = open_file(&artc_dir, "asc.tsv").unwrap();

    let asc_reader = get_buffer_from_file(asc_file).unwrap();
    let mut asc_map = HashMap::new();
    for line_result in asc_reader.lines() {
        let v: Vec<String> = split_by_tab(line_result.unwrap());
        let (fingerprint, url) = (&v[0], &v[1]);
        asc_map.insert(
            url.to_string(),
            ArtifactInfo {
                sig_type: SigType::Asc,
                value: fingerprint.to_string(),
                verified: true,
            },
        );
    }

    let sha_reader = get_buffer_from_file(sha_file).unwrap();
    let mut sha_map = HashMap::new();
    for line_result in sha_reader.lines() {
        let v: Vec<String> = split_by_tab(line_result.unwrap());
        let (hash, verified, url) = (&v[0], &v[1], &v[2]);
        sha_map.insert(
            url.to_string(),
            ArtifactInfo {
                sig_type: SigType::Sha,
                value: hash.to_string(),
                verified: (" ver " == verified),
            },
        );
    }

    merge(sha_map, asc_map)
}

fn manage_artifact_downloads(
    url: String,
    download_dir: &PathBuf,
    keys_dir: &PathBuf,
    log_file: &File,
    sha_file: &File,
    asc_file: &File,
) {
    let main_artifact_url = url.as_str();
    let main_artifact_filename = get_filename_from_url(&main_artifact_url, &download_dir).unwrap();
    let main_artifact: MainArtifact =
        Artifact::new(main_artifact_url, main_artifact_filename.as_path(), None);

    match &main_artifact.download() {
        Ok(_) => {}
        Err(e) => {
            log(e.to_string(), &log_file);
            ()
        }
    }

    let sha_url = main_artifact.append_url_ext("sha2");
    let sha_path = main_artifact.append_file_ext("sha2");
    let sha_artifact: ArtifactSha =
        Artifact::new(sha_url.as_str(), sha_path.as_path(), Some(&main_artifact));

    match &sha_artifact.download() {
        Ok(_) => match sha_artifact.check_hash() {
            Ok(sha_hash) => {
                tab_fmt3(sha_hash.hash, "ver".to_string(), sha_hash.url, &sha_file);
            }
            Err(e) => {
                log(e.to_string(), &log_file);
            }
        },
        Err(e) => {
            log(e.to_string(), &log_file);
            match &sha_artifact.get_hash() {
                Ok(hash) => {
                    tab_fmt3(
                        hash.to_string(),
                        "gen".to_string(),
                        sha_artifact.attached_artifact.url.to_string(),
                        &sha_file,
                    );
                }
                Err(e) => {
                    log(e.to_string(), &log_file);
                }
            }
        }
    }

    let mut ctx = GpgContext::from_protocol(Protocol::OpenPgp).unwrap();
    ctx.set_engine_home_dir("target/artc".to_string().into_cstr());

    let asc_url = main_artifact.append_url_ext("asc");
    let asc_path = main_artifact.append_file_ext("asc");
    let asc_artifact: ArtifactAsc =
        Artifact::new(asc_url.as_str(), asc_path.as_path(), Some(&main_artifact));

    match &asc_artifact.download() {
        Ok(_) => match verify_artifact(&asc_artifact, &keys_dir, &mut ctx) {
            Ok(key_id) => {
                tab_fmt2(key_id.id, key_id.url, &asc_file);
            }
            Err(e) => {
                log(e.to_string(), &log_file);
            }
        },
        Err(e) => {
            log(e.to_string(), &log_file);
        }
    }
}

enum Command {
    DownloadArtifacts,
    RbmConfigs,
    PackageArtifacts,
    NoCommand,
}
