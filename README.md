# WSL-cert-circus
Import Win Root CAs into WSL

## Background
Many companies use Deep Packet Inspection in their firewalls/proxies, which basically decrypt and re encrypt SSL traffic. 
For the clients to trust the re encrypted packages, the company installs a custom Root CA on them. But as WSL installs a full Linux distro, which comes with its own trust store, programs inside WSL to not trust those CAs. That results in SSL verification errors. 
This script solves it, by detecting installed CA certificates in windows trust store and importing them to WSL trust store. 

## Credits
Based on this [gist](https://gist.github.com/emilwojcik93/7eb1e172f8bb038e324c6e4a7f4ccaaa)

## Changes
- Use Certificate Subject instead of Issuer as certificate identifier
- add "AllCertificates" Parameter to just load all of the found certificates instead of stopping after the first successfull one
- add podman-machine-default (basically fedora) as possible WSL distro
