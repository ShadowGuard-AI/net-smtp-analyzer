# net-smtp-analyzer
Actively probes an SMTP server with three checks: it grabs the server banner, tests STARTTLS support, and tests for an open relay. That is the whole tool: it does not capture SMTP traffic and it does not test authentication mechanisms. - Focused on Basic network operations

The open relay test stops after RCPT TO by default and reports the relay result from that reply; no message is sent. Sending a message happens only under `--send-test-message` (with `-o`), which delivers a real test message to the recipient named by `--recipient`, so `--recipient` is required with that flag and the flag refuses at exit 1 when no recipient is named. The delivered message carries the subject "Open relay test message from net-smtp-analyzer" and a body that plainly marks it as an open relay test message from this tool.

The tool uses only the Python standard library, so there is nothing else to install. If no connection to the target can be made, the tool exits 1 and does not report a completed analysis.

## Install
`git clone https://github.com/ShadowStrikeHQ/net-smtp-analyzer`

## Usage
`python3 main.py <target> [params]`

## Parameters
- `target`: The target SMTP server (hostname or IP address). Required positional argument.
- `-h`: Show help message and exit
- `-p`, `--port`: The port number to connect to (default: 25).
- `-s`, `--starttls`: Attempt to use STARTTLS.
- `-o`, `--openrelay`: Test for open relay vulnerability. By default the test stops after RCPT TO and sends no message.
- `--send-test-message`: With `-o`, deliver a real, clearly marked open relay test message to the recipient named by `--recipient`. Requires `--recipient`.
- `-v`, `--verbose`: Enable verbose output (debug logging).
- `-d`, `--domain`: Specify the domain name for HELO/EHLO command (default: target).
- `--sender`: Sender address for open relay testing (default: test@example.com).
- `--recipient`: Recipient address for open relay testing. Required with `--send-test-message`. For a RCPT TO only probe with no recipient named, the sender address is used as the probe recipient and no message is sent.

## License
Copyright (c) ShadowStrikeHQ
