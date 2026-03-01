// jshint esversion: 6

// This code will check that the pull request has been approved via GitHub
// review approval by a minimum number of reviewers and by all assignees, and
// that no changes were requested by any reviewers.  Only reviewers with write
// access to the repository are considered.
//
// This is very similar to GitHub's built-in branch protection option to require
// pull request reviews before merging, but allows for much more flexibility and
// customization.

// dependencies: lodash4

// Helper function to check if a user is a bot.
function isBotAuthor(author) {
  return (
    author.username.endsWith("[bot]") || author.username.startsWith("toktok-")
  );
}

function equals(a) {
  return (b) => a === b;
}

// The number of approvals required to merge: at least 2 humans must approve the
// code. If the author is a bot, then 2 approvals are required; otherwise, only
// 1 approval is required (because 1 human wrote the code, so they approve).
let numApprovalsRequired = isBotAuthor(review.pullRequest.author) ? 2 : 1;

const approvals = review.pullRequest.approvals;

let numApprovals = _.filter(approvals, equals("approved")).length;
const numRejections = _.filter(approvals, equals("changes_requested")).length;

const discussionBlockers = _(review.discussions)
  .filter((x) => !x.resolved)
  .flatMap("participants")
  .filter((x) => !x.resolved)
  .map((user) => _.pick(user, "username"))
  .value();

let pendingReviewers = _(discussionBlockers)
  .map((user) => _.pick(user, "username"))
  .concat(review.pullRequest.requestedReviewers)
  .value();

const required = _.map(review.pullRequest.assignees, "username");
_.pull(required, review.pullRequest.author.username);
if (required.length) {
  numApprovalsRequired = _.max([required.length, numApprovalsRequired]);
  numApprovals =
    _(approvals).pick(required).filter(equals("approved")).size() +
    _.min([numApprovals, numApprovalsRequired - required.length]);
  pendingReviewers = _(required)
    .reject((username) => approvals[username] === "approved")
    .reject((username) => pendingReviewers.length && approvals[username])
    .map((username) => ({ username }))
    .concat(pendingReviewers)
    .value();
}

pendingReviewers = _.uniqBy(pendingReviewers, "username");

const description =
  (numRejections ? `${numRejections} change requests, ` : "") +
  `${numApprovals} of ${numApprovalsRequired} approvals obtained`;
const shortDescription =
  (numRejections ? `${numRejections} ✗, ` : "") +
  `${numApprovals} of ${numApprovalsRequired} ✓`;

return {
  completed: numApprovals >= numApprovalsRequired,
  description,
  shortDescription,
  pendingReviewers,
};
