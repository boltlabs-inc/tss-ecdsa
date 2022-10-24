# Contributing to tss-ecdsa

If you find an error, please submit an issue describing the problem and expected behavior.

## Code of Conduct

Please be kind, courteous, and respectful. This project, although not formally affiliated with the Rust project, supports the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
Please report any violations of this code of conduct to
[conduct@boltlabs.io](mailto:conduct@boltlabs.io).


## Understanding inline issues
Issues are described in the issue tracker, but there is also supporting inline documentation noting the specific location of various types of problems in the code. These are marked as `TODO #(issue) (optional modifiers):`. Potential modifiers include:
- `design`: Solving the issue requires addressing an open design question
- `implementation`: Solving the issue requires building out some aspect of the implementation that didn't exist at time of writing


## Definition of Done
Below we define the criteria for determining whether an issue or set of issues can be considered as "done."

### Making issues
Before taking on a new issue, it is important to make sure that the issues being made are clear and outline a specific task.  Below are some helpful criteria for what makes a good issue:

1. Issues must include a description stating the problem and providing any necessary context.
    1. As part of context, it may be helpful to link to design specification documents, PRs, or other issues.
2. Issues must list criteria for closing e.g:
    1. What functionality/logic must exist for the problem described to be solved or addressed?
    2. Are there any issues that should be made as a product of this issue?
    3. What tests need to be written as part of this issue?
3. Issues must be tagged with the appropriate epic(s).

### Making and Reviewing PRs
Once you, as the developer, have worked on a well-defined issue or set of issues (as described above), you can use the following list of criteria to see if your code is ready for review. The PR reviewer, who should be a different person from the developer, can use the same list for their review as well.

Aside from checking that the general functionality and logic of the code addresses the issue(s) at hand, you and the reviewer should check that:
1. The developer has rebased with `main` before marking the code as ready for review. This is to make sure the code is as up-to-date as possible and to make merging easier after the review.
2. All "checks" pass. This repo's Github actions runs a formatting check (`rustfmt`), a linting check (`clippy`), and runs all unit and integration tests in the repo. It may be helpful, as the developer, to make a draft PR so that Github can run these checks for you instead of having to run them locally.
3. The code is readable and self-explanatory for the reader, and there are comments where appropriate to provide clarity.
4. All APIs are documented.
5. Commit messages are linked with the relevant issues number(s).
6. The new code has testing infrastructure - this includes appropriate unit tests and/or integration tests, and issues to describe plans for creating any testing infrastructure that could not be included in the PR.
7. Any TODOs left in the code are marked with an associated issue number to an issue that is defined using the above criteria.


#### An issue is done after:
1. The developer thinks their code passes the above criteria and marks the code for review.
2. The PR reviewer approves the code using the same criteria.
3. The developer rebases their branch with `main` again to catch any changes that may have happened during the review period.
4. The developer merges their PR branch into `main` (or whichever branch they initially branched from). This should also close any relevant issues from the PR and delete the PR branch.
