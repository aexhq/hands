# Hosted Brain with the AWS Hand

`brain-hand-aws` composes the pinned Brain revision, Brain's DynamoDB and KMS adapters, and Hands'
Lambda MicroVM `HandFactory`. It contains no product-specific tools, identity, billing, output
validation, or routing.

Required settings:

- `BRAIN_API_TOKEN`
- `BRAIN_JOURNAL_TABLE`
- `BRAIN_KMS_KEY_ID`
- `HAND_IMAGE`
- `HAND_IMAGE_VERSION`
- `HAND_STORAGE_BUCKET`

`AWS_REGION` defaults to `eu-west-1`; `BRAIN_LISTEN` defaults to loopback port 8700. A trusted
server-tool service is optional, but `BRAIN_EXTERNAL_TOOL_EXECUTOR_URL`,
`BRAIN_EXTERNAL_TOOL_EXECUTOR_TOKEN`, and `BRAIN_EXTERNAL_TOOL_CAPABILITIES` must be configured
together. Those credentials never enter a session prefix or Hand.

The image is published as `ghcr.io/aexhq/brain-hand-aws:sha-<hands-commit>`. That Hands commit pins
the exact Brain revision, so the image identity recovers both source inputs.
