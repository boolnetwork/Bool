# Bool

[BOOL Network](https://bool.network/) is a heterogeneous cross-chain network using Secure Multi-Party Computation technology.

Bool is the project name based on substrate implementation.

**Documentation**

To understand how BOOL Network works, read our [docs](https://docs.bool.network/docs/introduction/main.html).

## Trying it out

Simply go to [substrate.dev](https://substrate.dev).

### Build and run

1. Clone bool project

```shell
git clone https://github.com/boolnetwork/Bool.git
```

2. Initialize environment

```shell
cd Bool
bash ./scripts/init.sh
```

*Note: The basic environment settings same as the substrate , refer to [installation](https://substrate.dev/docs/en/knowledgebase/getting-started/)*.

3. Build node

```shell
cargo build --release
```

4. Run with dev mode

```shell
./target/release/Bool --dev
```

------

## Contributing

All PRs are welcome! Please follow our contributing guidelines [here](CONTRIBUTING.md).