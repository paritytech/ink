# How to release

Generally, we bump and publish the versions of all crates in this
mono-repository in lockstep.
It does not matter if it's a `PATCH`, `MINOR`, `MAJOR` release.

Reasons for doing it this way:
* Keeps our [`RELEASES.md`](https://github.com/paritytech/ink/blob/v3.x.x/RELEASES.md)
  simple and easy to grasp.<br>
  We can still bundle all changes there together and don't have to go to a
  more fine-grained crate level.
* Easier to follow reported issues.<br>
  All crates are closely tied together anyway and if someone reports an issue with
  e.g. `3.1` we know what they mean.
* Easier to keep the workshop/documentation/playground/user interfaces in sync.
* Easier for users to follow changes.<br>
  Those will all be listed in one section of the changelog, bundled together,
  released at the same time.
* Third party tooling like dependabot can easily extract the changelog.

## Examples

Examples (so anything in the `examples/` folder) are a bit of a special case in our
release pipeline since they are considered as ink! internals and not part of the library
per-say.

What this means is that any changes to the examples (breaking or not) should only be
considered a `PATCH` level change. Additionally, they should not be published to
crates.io.


## Checklist

We'll be using [`cargo-release`](https://github.com/crate-ci/cargo-release) to release 
ink!. There are still a few manual steps though, and we hope to make this more streamlined 
in the future.

1. Create a new feature branch off `v3.x.x`.
1. Copy the release notes that appear in the [`RELEASES.md`](https://github.com/paritytech/ink/blob/v3.x.x/RELEASES.md) 
   into the PR description.
   - This will cause the individual PRs to be linked to the release in which they are 
     included.
1. Bump the version in all TOML files to the new version.
    ```
    find . -type f -name *.toml -exec sed -i -e 's/$OLD_VERSION/$NEW_VERSION/g' {} \;
    ```
1. Make sure you've moved the changes in the `RELEASES.md` from `[Unreleased]` into a new
   section for the release.
1. Check that all notable PRs since the last release are now in the new release section,
   in case the `[Unreleased]` section was incomplete.<br>
   - Notable changes are changes that affect users in some way. This means that something
     like a change to our CI pipeline is likely not notable and should not be included.
1. Make sure you've merged the latest `v3.x.x` into your branch.
1. Open a release PR
    - Wait for approvals from Core team members.
    - Ensure the entire CI pipeline is green.
1. Do a dry run with `cargo release [new_version] -v --no-tag --no-push`
    - `[new_version]` should be the **exact** SemVer compatible version you are attempting 
      to release e.g. `4.0.0-alpha.3`
      - It is possible to supply a SemVer level here e.g. `major`, `minor`, `patch` or 
        `<pre-release-name>`, however this will automatically bump and commit the changes 
        to the `Cargo.toml` manifests. We have already done that in an earlier step so it 
        is not necessary.
    - We don't want `cargo-release` to create any releases or push any code, we'll do
      that manually once we've actually published to `crates.io`.
1. Check the output of the dry run:
   - Does not show any automatic bumping of crate versions.
   - Runs without error.
1. Following a successful dry run, we can now publish to crates.io.
   - This will be done from the release branch itself.
   - This is because it is possible for the dry run to succeed but for the actual publish 
     to fail and require some changes. So before running the next step:
     - Ensure there have been no new commits to `v3.x.x` which are not included in this 
       branch.
     - Notify core team members in the Element channel that no PRs should be merged to 
       `v3.x.x` during the release.
     - The above are to ensure that the bundled code pushed to crates.io is the same as 
       the tagged release on GitHub.
1. Publish with `export PUBLISH_GRACE_SLEEP=5 && cargo release [new_version] -v --no-tag --no-push --execute`
    - Ensure the same `[new_version]` as the dry run, which should be the **exact** SemVer 
      compatible version you are attempting to release e.g. `4.0.0-alpha.3`.
    - We add the grace period since crates depend on one another.
    - We add the `--execute` flag to _actually_ publish things to crates.io.
1. Following a successful release from the release PR branch, now the PR can be merged 
   into `v3.x.x`
    - Once merged, notify core team members in the Element channel that PRs can be merged 
      again into `v3.x.x`
1. Replace `vX.X.X` with the new version in the following command and then execute it:
    ```
    git tag -s vX.X.X && git push origin vX.X.X
    ```
    - Ensure your tag is signed with an offline GPG key!
    - Alternatively, the `Create release` GitHub UI below allows creating this tag when 
      creating the release.
1. Create a GitHub release for this tag. In the [tag overview](https://github.com/paritytech/ink/tags)
   you'll see your new tag appear. Click the `…` on the right of the tag and then 
   `Create release`.
1. Paste the release notes that appear in the [`RELEASES.md`](https://github.com/paritytech/ink/blob/v3.x.x/RELEASES.md)
   there. The title of the release should be `vX.X.X`.
1. Post an announcement to those Element channels:
    * [Smart Contracts & Parity ink!](https://matrix.to/#/#ink:matrix.parity.io)
