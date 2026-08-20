# Hosted Brain with the AWS Hand

`brain-hand-aws` is a downstream composition, not a fork of Brain. It combines the immutable Brain
revision pinned in the workspace with Brain's neutral DynamoDB/KMS adapters and Hands' Lambda
MicroVM `HandFactory`. The binary contains no Aex tool names, output validation, identity, billing,
or product routing.

Required settings are `BRAIN_API_TOKEN`, `BRAIN_JOURNAL_TABLE`, `BRAIN_KMS_KEY_ID`, `HAND_IMAGE`,
`HAND_IMAGE_VERSION`, and `HAND_STORAGE_BUCKET`; `AWS_REGION` defaults to `eu-west-1` and
`BRAIN_LISTEN` defaults to loopback port 8700. A trusted server-Tool service is optional, but its
`BRAIN_EXTERNAL_TOOL_EXECUTOR_URL`, `BRAIN_EXTERNAL_TOOL_EXECUTOR_TOKEN`, and comma-separated
`BRAIN_EXTERNAL_TOOL_CAPABILITIES` must be configured together. Credentials never enter a session
prefix or Hand.

The image is published as `ghcr.io/aexhq/brain-hand-aws:sha-<hands commit>`. That Hands commit pins
the exact Brain source revision, making the one image identity sufficient to recover both inputs.
