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

//! # ArtiConf
//!
//! `articonf` is a program for downloading artifacts and verifying the sha hashes and pgp signatures.
//! The program can also generate Tor RBM config files and can package artifacts into a maven repo.

pub mod artifacts;
pub mod prelude;

extern crate cstr_argument;
extern crate digest;
extern crate flate2;
extern crate gpgme;
extern crate reqwest;
extern crate sha2;
extern crate tar;
