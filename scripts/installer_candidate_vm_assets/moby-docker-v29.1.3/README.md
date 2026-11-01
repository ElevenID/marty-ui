# Upstream rootless Docker sources

These two shell files are unmodified Moby sources from the Docker Engine
`docker-v29.1.3` tag. The tag has the `docker-` prefix in the upstream repository.
The accompanying `LICENSE` and `NOTICE` are retained from that same tag.

| File | SHA-256 |
| --- | --- |
| `dockerd-rootless.sh` | `8eb00d61b5e78ffc0dcd628f056389b5859cc61d6fe3ce17b4a3a4b08143c8a5` |
| `dockerd-rootless-setuptool.sh` | `e68ef6550fea1b5c01b5cc7a400a6b44ee28159d7714758c3845759e03e079dc` |
| `LICENSE` | `7c87873291f289713ac5df48b1f2010eb6963752bbd6b530416ab99fc37914a8` |
| `NOTICE` | `b40ec5b16182103ef1cd69d42a21c98369e35bd483b3973902da4807c0755446` |

Sources:

- <https://github.com/moby/moby/blob/docker-v29.1.3/contrib/dockerd-rootless.sh>
- <https://github.com/moby/moby/blob/docker-v29.1.3/contrib/dockerd-rootless-setuptool.sh>
- <https://github.com/moby/moby/blob/docker-v29.1.3/LICENSE>
- <https://github.com/moby/moby/blob/docker-v29.1.3/NOTICE>

The optional disposable VM seed validates these exact bytes and renders them
into root-owned guest files only after an explicit rootless resource-profile
selection. Importing the Python modules, inspecting the assets or rendering a
seed does not execute these scripts. They are not an installer for an existing
customer host. The controller never downloads a setup script at guest runtime.

The pinned Ubuntu 24.04 `docker.io` package omits these two helpers. Its normal
Docker binaries and the separately pinned rootless prerequisites remain supplied
by Ubuntu packages. No second package repository is introduced. A change to the
package policy or these assets requires a deliberate hash/policy update and
fresh disposable-guest qualification; the retained v1 policy remains unchanged.
