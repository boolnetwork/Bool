# How to contribute

Welcome to the contributions page!

If you want to contribute to a project and make it better, your help is very welcome. Contributing is also a great way to learn more about social coding on Github, new technologies and and their ecosystems and how to make constructive, helpful bug reports, feature requests and the noblest of all contributions: a good, clean pull request.

## Steps

Here are the steps to follow for your contribution!

1. fork the repo under your GitHub account
2. work on an issue, bounty or any other form of a contribution under your fork
3. format your code using `cargo fmt`
4. build and test your code locally with `cargo build` and `cargo test --all`
5. create a pull request merging from your fork into our repo

## Pull request checklist

When creating a PR, please make sure to run through the following checklist:

- [ ] Add a description summarizing the PR, e.g.:
    - What does it do?
    - What important points should reviewers know?
    - Is there something left for follow-up PRs?
    - For large diffs please include a changelog in the description with a bulleted "Adds | Changes | Fixes | Removes" sections
- [ ] Mention the related issue, if any, e.g. Fixes #228 or Related #1337.
- [ ] Unit tests
- [ ] Integration tests, if appropriate
- [ ] Request reviewers. If you aren't sure, start with GH suggestions.
- [ ] Update rustdoc comments with changes
- [ ] Update README with changes, if appropriate
- [ ] Bumped the runtime version if there are breaking changes in the runtime.

## Review process

Include suggested reviewers for your PR and wait for the review.

## Merge process

Don't worry about merging! We will merge once everything is good!