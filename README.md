# ssh-union-agent

An SSH agent that forwards requests to multiple upstream SSH agents, presenting a unified view of all available keys.

## Features

- Combines keys from multiple upstream SSH agents into a single agent
- Deduplicates keys when the same key exists in multiple upstream agents
- Tries each upstream agent in order when signing until one succeeds
- Compatible with standard SSH tools via `SSH_AUTH_SOCK`

## Installation

### Using Nix Flakes

```bash
nix build
./result/bin/ssh-union-agent
```

### Using Go

```bash
go build -o ssh-union-agent .
```

## Usage

```
ssh-union-agent [-socket <path>] <upstream-socket>...
```

### Options

- `-socket <path>` - Path for the union agent's socket. If not specified, a socket is automatically created.

### Arguments

- `upstream-socket` - One or more paths to upstream SSH agent sockets.

### Examples

Start the agent with two upstream agents:

```bash
ssh-union-agent /run/user/1000/gnupg/S.gpg-agent.ssh ~/.ssh/agent.sock
```

Use with `eval` to set environment variables:

```bash
eval $(ssh-union-agent /path/to/agent1.sock /path/to/agent2.sock)
ssh-add -l  # Lists keys from both agents
```

Specify a custom socket path:

```bash
ssh-union-agent -socket /tmp/my-union-agent.sock /path/to/agent1.sock /path/to/agent2.sock
```

## How It Works

- **List**: Returns all keys from all upstream agents, with duplicates removed.
- **Sign**: Tries each upstream agent in order until one successfully signs.
- **Add**: Forwards to the first upstream agent.
- **Remove/Lock/Unlock**: Forwards to all upstream agents.

## Development

Enter a development shell with Go:

```bash
nix develop
```

Build and run:

```bash
go build -o ssh-union-agent .
./ssh-union-agent -h
```

## License

MIT
