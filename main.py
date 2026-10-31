import socket
import argparse
import logging
import ssl
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the SMTP analyzer.
    """
    parser = argparse.ArgumentParser(description='Actively probes an SMTP server: banner grab, STARTTLS check, and open relay check.')
    parser.add_argument('target', help='The target SMTP server (hostname or IP address).')
    parser.add_argument('-p', '--port', type=int, default=25, help='The port number to connect to (default: 25).')
    parser.add_argument('-s', '--starttls', action='store_true', help='Attempt to use STARTTLS.')
    parser.add_argument('-o', '--openrelay', action='store_true', help='Test for open relay: by default the test stops after RCPT TO and reports the result from that reply, sending no message.')
    parser.add_argument('--send-test-message', action='store_true', help='With -o, after RCPT TO is accepted, deliver a real, clearly marked open relay test message to the recipient named by --recipient. --recipient is required with this flag; without a recipient the flag refuses and exits 1.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    parser.add_argument('-d', '--domain', type=str, help='Specify the domain name for HELO/EHLO command (default: target).')
    parser.add_argument('--sender', type=str, default='test@example.com', help='Sender address for open relay testing (default: test@example.com).')
    parser.add_argument('--recipient', type=str, default=None, help='Recipient address for open relay testing. Required with --send-test-message. For a RCPT TO only probe with no recipient named, the sender address is used as the probe recipient and no message is sent.')

    return parser.parse_args()

class ReplyReader:
    """
    Reads SMTP replies until the terminating line of a reply. A multi
    line reply continues on lines of the form 250-text and ends on a
    line of the form 250 text, and the fragments may arrive split
    across packets, so reading continues until that terminating line
    and the assembled text is returned.
    """

    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""

    def read_reply(self):
        lines = []
        while True:
            while b"\r\n" not in self.buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return "\n".join(lines)
                self.buffer += chunk
            raw_line, self.buffer = self.buffer.split(b"\r\n", 1)
            line = raw_line.decode('utf-8', errors='ignore')
            lines.append(line)
            if len(line) < 4 or line[3] != "-":
                return "\n".join(lines)

def test_open_relay(server, port, sender, recipient, domain, send_test_message=False):
    """
    Tests for an open relay vulnerability. By default the test stops
    after RCPT TO and reports the relay result from that reply. A real
    test message is delivered only when send_test_message is set.
    """
    probe_recipient = recipient if recipient else sender
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, port))
        reader = ReplyReader(sock)
        response = reader.read_reply()
        logging.debug(f"Initial response: {response.strip()}")

        sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"EHLO response: {response.strip()}")

        sock.send(f"MAIL FROM:<{sender}>\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"MAIL FROM response: {response.strip()}")
        if not response.startswith("250"):
            logging.warning(f"MAIL FROM command failed: {response.strip()}")
            sock.close()
            return False

        sock.send(f"RCPT TO:<{probe_recipient}>\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"RCPT TO response: {response.strip()}")
        if not response.startswith("250") and not response.startswith("251"):
            logging.warning(f"RCPT TO command failed: {response.strip()}")
            sock.close()
            return False

        if not send_test_message:
            sock.close()
            logging.info("Open relay test: RCPT TO was accepted, so the server appears to relay for this sender and recipient. No message was sent; the test stopped after RCPT TO.")
            return True

        sock.send("DATA\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"DATA response: {response.strip()}")
        if not response.startswith("354"):
            logging.warning(f"DATA command failed: {response.strip()}")
            sock.close()
            return False

        message = ("Subject: Open relay test message from net-smtp-analyzer\r\n"
                   "\r\n"
                   "This is an open relay test message sent by the net-smtp-analyzer tool.\r\n"
                   "It was delivered deliberately by the operator of that tool to test whether this server relays mail.\r\n"
                   ".\r\n")
        sock.send(message.encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"Data transmission response: {response.strip()}")
        if not response.startswith("250"):
            logging.warning(f"Data transmission failed: {response.strip()}")
            sock.close()
            return False

        sock.send("QUIT\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"QUIT response: {response.strip()}")
        sock.close()
        logging.info("Open relay test: the marked test message was delivered to the named recipient.")
        return True

    except socket.timeout:
        logging.error("Socket timeout during open relay test.")
        return False
    except socket.error as e:
        logging.error(f"Socket error during open relay test: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during open relay test: {e}")
        return False

def test_starttls(server, port, domain):
    """
    Tests for STARTTLS support.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, port))
        reader = ReplyReader(sock)
        response = reader.read_reply()
        logging.debug(f"Initial response: {response.strip()}")

        sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"EHLO response: {response.strip()}")

        if "STARTTLS" not in response.upper():
            logging.warning("STARTTLS is not supported.")
            sock.close()
            return False

        sock.send("STARTTLS\r\n".encode('utf-8'))
        response = reader.read_reply()
        logging.debug(f"STARTTLS response: {response.strip()}")
        if not response.startswith("220"):
            logging.warning(f"STARTTLS command failed: {response.strip()}")
            sock.close()
            return False

        context = ssl.create_default_context()
        secure_sock = context.wrap_socket(sock, server_hostname=server)
        secure_reader = ReplyReader(secure_sock)

        logging.info("STARTTLS negotiation successful.")

        secure_sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = secure_reader.read_reply()
        logging.debug(f"EHLO response after STARTTLS: {response.strip()}")

        secure_sock.send("QUIT\r\n".encode('utf-8'))
        response = secure_reader.read_reply()
        logging.debug(f"QUIT response after STARTTLS: {response.strip()}")
        secure_sock.close()
        return True

    except socket.timeout:
        logging.error("Socket timeout during STARTTLS test.")
        return False
    except socket.error as e:
        logging.error(f"Socket error during STARTTLS test: {e}")
        return False
    except ssl.SSLError as e:
        logging.error(f"SSL error during STARTTLS test: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during STARTTLS test: {e}")
        return False

def banner_grab(server, port):
    """
    Grabs the SMTP banner. Returns the banner text, or None when no
    connection to the target could be made.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((server, port))
        reader = ReplyReader(sock)
        response = reader.read_reply()
        logging.info(f"SMTP Banner: {response.strip()}")
        sock.close()
        return response.strip()
    except socket.timeout:
        logging.error("Socket timeout during banner grab.")
        return None
    except socket.error as e:
        logging.error(f"Socket error during banner grab: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during banner grab: {e}")
        return None

def main():
    """
    Main function to orchestrate the SMTP analyzer. Returns 1 when no
    connection to the target could be made, and 0 after at least one
    test ran against a reached target.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.send_test_message and not args.recipient:
        logging.error("Error: --send-test-message requires a recipient named with --recipient; no message was sent.")
        print("Error: --send-test-message requires a recipient named with --recipient; no message was sent.")
        return 1

    server = args.target
    port = args.port
    domain = args.domain if args.domain else server

    logging.info(f"Starting SMTP analysis for {server}:{port}")

    banner = banner_grab(server, port)
    if banner is None:
        logging.error("No connection to the target could be made; no analysis was performed.")
        return 1

    tests_ran = 1

    if args.starttls:
        logging.info("Testing for STARTTLS support...")
        test_starttls(server, port, domain)
        tests_ran += 1

    if args.openrelay:
        logging.info("Testing for open relay vulnerability...")
        test_open_relay(server, port, args.sender, args.recipient, domain, send_test_message=args.send_test_message)
        tests_ran += 1

    if tests_ran < 1:
        logging.error("No test ran; no analysis was performed.")
        return 1

    logging.info("SMTP analysis completed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
