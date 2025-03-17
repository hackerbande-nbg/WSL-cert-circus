# WSL-cert-circus
Import Win Root CAs into WSL

## Credits
Based on this [gist]([https://gist.github.com/emilwojcik93/7eb1e172f8bb038e324c6e4a7f4ccaaa)

## Changes
- Use Certificate Subject instead of Issuer as certificate identifier
- add "AllCertificates" Parameter to just load all of the found certificates instead of stopping after the first successfull one
- add podman-machine-default (basically fedora) as possible WSL distro