import socket
import argparse
import logging
import ssl
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the SMTP analyzer.
    """
    parser = argparse.ArgumentParser(description='Analyzes SMTP traffic for potential vulnerabilities.')
    parser.add_argument('target', help='The target SMTP server (hostname or IP address).')
    parser.add_argument('-p', '--port', type=int, default=25, help='The port number to connect to (default: 25).')
    parser.add_argument('-s', '--starttls', action='store_true', help='Attempt to use STARTTLS.')
    parser.add_argument('-o', '--openrelay', action='store_true', help='Attempt to test for open relay vulnerability.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    parser.add_argument('-d', '--domain', type=str, help='Specify the domain name for HELO/EHLO command (default: target).')
    parser.add_argument('--sender', type=str, default='test@example.com', help='Sender address for open relay testing (default: test@example.com).')
    parser.add_argument('--recipient', type=str, default='test@example.com', help='Recipient address for open relay testing (default: test@example.com).')

    return parser.parse_args()

def test_open_relay(server, port, sender, recipient, domain):
    """
    Tests for an open relay vulnerability.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set a timeout for the connection
        sock.connect((server, port))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"Initial response: {response.strip()}")

        sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"EHLO response: {response.strip()}")

        sock.send(f"MAIL FROM:<{sender}>\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"MAIL FROM response: {response.strip()}")
        if not response.startswith("250"):
            logging.warning(f"MAIL FROM command failed: {response.strip()}")
            sock.close()
            return False

        sock.send(f"RCPT TO:<{recipient}>\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"RCPT TO response: {response.strip()}")
        if not response.startswith("250") and not response.startswith("251"): #251 is also a success code
            logging.warning(f"RCPT TO command failed: {response.strip()}")
            sock.close()
            return False

        sock.send(f"DATA\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"DATA response: {response.strip()}")
        if not response.startswith("354"):
            logging.warning(f"DATA command failed: {response.strip()}")
            sock.close()
            return False

        sock.send("Subject: Test Email\r\n\r\nThis is a test email.\r\n.\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"Data transmission response: {response.strip()}")
        if not response.startswith("250"):
             logging.warning(f"Data transmission failed: {response.strip()}")
             sock.close()
             return False

        sock.send("QUIT\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"QUIT response: {response.strip()}")
        sock.close()
        logging.info("Open relay test successful (email likely sent).")
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
        sock.settimeout(5)  # Set a timeout for the connection
        sock.connect((server, port))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"Initial response: {response.strip()}")

        sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"EHLO response: {response.strip()}")

        if "STARTTLS" not in response.upper():
            logging.warning("STARTTLS is not supported.")
            sock.close()
            return False

        sock.send("STARTTLS\r\n".encode('utf-8'))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"STARTTLS response: {response.strip()}")
        if not response.startswith("220"):
            logging.warning(f"STARTTLS command failed: {response.strip()}")
            sock.close()
            return False

        context = ssl.create_default_context()
        secure_sock = context.wrap_socket(sock, server_hostname=server)

        logging.info("STARTTLS negotiation successful.")

        secure_sock.send(f"EHLO {domain}\r\n".encode('utf-8'))
        response = secure_sock.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"EHLO response after STARTTLS: {response.strip()}")

        secure_sock.send("QUIT\r\n".encode('utf-8'))
        response = secure_sock.recv(1024).decode('utf-8', errors='ignore')
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
    Grabs the SMTP banner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set a timeout for the connection
        sock.connect((server, port))
        response = sock.recv(1024).decode('utf-8', errors='ignore')
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
    Main function to orchestrate the SMTP analyzer.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    server = args.target
    port = args.port
    domain = args.domain if args.domain else server  # Use the target as the domain if not provided

    logging.info(f"Starting SMTP analysis for {server}:{port}")

    banner_grab(server, port)

    if args.starttls:
        logging.info("Testing for STARTTLS support...")
        test_starttls(server, port, domain)

    if args.openrelay:
        logging.info("Testing for open relay vulnerability...")
        test_open_relay(server, port, args.sender, args.recipient, domain)

    logging.info("SMTP analysis completed.")

if __name__ == "__main__":
    main()