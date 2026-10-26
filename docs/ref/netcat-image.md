# Netcat fork container build

The fork workflow builds `ghcr.io/netcat-ai/headscale` from a clean checkout,
with a full-commit `sha-<commit>` tag and an immutable manifest digest. It never
deploys to a server. Upstream workflows remain unchanged.

Before implementing the isolated image acceptance script, identified failures:

- The fork workflow may be skipped, lack GHCR write access, or publish the wrong repository/revision.
- The index may omit AMD64 or ARM64, or one platform may not actually start.
- Dirty build metadata may poison the stored database version.
- TencentCloud provider may be absent or reject valid configuration.
- Migration may lose nodes, routes, tags, credential hashes, foreign keys or sequences.
- Existing API credentials may stop authenticating after migration.
- Repeated startup may repeat or change migrations.
- A backup may not restore exactly, or the old image may fail against the restored database.
- Test containers, keys or database dumps may escape cleanup/artifacts.

Acceptance uses native GitHub AMD64 and ARM64 runners, PostgreSQL 18.6 and the
pinned old production image, with synthetic users, credentials and a debug node.
No production credentials/database are sent to GitHub. Reports contain only
image identities and checks; ephemeral database dumps and keys are not uploaded.
The image's TencentCloud config is checked without calling DNSPod. Real DNS-01
issuance was tested separately; image acceptance does not issue a certificate.

Triggers: changes on `main` or `codex/tencentcloud-dns`, or manual dispatch once
the workflow exists on the default branch. Failed verification does not deploy
anything. Treat only a successful whole workflow as an accepted image, even if
its build job already pushed a candidate tag.

After success, use the `image-reference` artifact and both `image-verification-*`
reports. Pull/deploy by digest, take a fresh final database/config/key backup,
and follow the separately rehearsed database restore rollback procedure.
