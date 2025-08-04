import os
import subprocess
import tempfile
import pickle
import base64
import sys

# --- 1. Hardcoded Secret (Detected by 'secret' scanner) ---
# This is a very common and easily detectable vulnerability.
DATABASE_PASSWORD = "mySuperSecretPassword123"
API_KEY = "sk_live_abcdef1234567890abcdef1234567890" # Looks like a Stripe API key

def connect_to_database():
    """Simulates connecting to a database using a hardcoded password."""
    print(f"Connecting to DB with password: {DATABASE_PASSWORD}")
    # In a real app, this would use a database driver
    # Trivy will flag DATABASE_PASSWORD and API_KEY

def send_api_request():
    """Simulates sending an API request with a hardcoded key."""
    print(f"Sending API request with key: {API_KEY}")

# --- 2. Insecure Temporary File Creation (Detected by 'misconfig' / 'vuln' if using outdated lib) ---
# Using tempfile.mktemp() is insecure due to race conditions.
# Trivy (and many other static analysis tools) often flag this.
def create_insecure_temp_file(data):
    """
    Creates an insecure temporary file using tempfile.mktemp().
    This can be exploited via a race condition.
    """
    temp_filename = tempfile.mktemp(suffix=".tmp", prefix="insecure_")
    print(f"Creating insecure temporary file: {temp_filename}")
    try:
        with open(temp_filename, "w") as f:
            f.write(data)
        print(f"Data written to {temp_filename}")
        # In a real scenario, this file might be processed, then deleted.
        # A malicious actor could create a file with the same name between mktemp() and open().
    except Exception as e:
        print(f"Error creating temp file: {e}")
    finally:
        # For demonstration, we'll try to clean up, but the vulnerability is in the creation.
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

# --- 3. Insecure Deserialization with pickle (Detected by 'vuln' / 'misconfig') ---
# Deserializing untrusted data with pickle.loads() can lead to Remote Code Execution (RCE).
# This is a critical vulnerability.
class RCEPayload:
    def __reduce__(self):
        # This will execute an arbitrary command when deserialized
        # In a real attack, this would be a malicious command.
        return (subprocess.Popen, (['echo', 'Insecure deserialization vulnerability detected!'],))

def process_serialized_data(encoded_data):
    """
    Deserializes base64-encoded, pickled data.
    Vulnerable if 'encoded_data' comes from untrusted input.
    """
    try:
        decoded_data = base64.b64decode(encoded_data)
        # The vulnerability is here: pickle.loads() on untrusted data
        deserialized_object = pickle.loads(decoded_data)
        print(f"Deserialized data: {deserialized_object}")
    except Exception as e:
        print(f"Error during deserialization: {e}")

# --- 4. OS Command Injection (Example of a 'misconfig' / 'vuln' depending on context) ---
# Direct string interpolation into subprocess calls can lead to command injection.
def execute_command_vulnerable(user_input):
    """
    Vulnerable to OS command injection.
    If user_input is '&& rm -rf /', it could be catastrophic.
    """
    command = "ls -l " + user_input
    print(f"Executing command: {command}")
    try:
        subprocess.run(command, shell=True, check=True) # shell=True is often the culprit
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
    except FileNotFoundError:
        print(f"Command not found for input: {user_input}")


if __name__ == "__main__":
    print("--- Running vulnerable functions ---")

    # Hardcoded secrets
    connect_to_database()
    send_api_request()

    # Insecure temporary file
    create_insecure_temp_file("Some sensitive temporary data.")

    # Insecure deserialization
    print("\n--- Testing insecure deserialization ---")
    # Generate a payload that will trigger RCE on deserialization
    malicious_payload = pickle.dumps(RCEPayload())
    base64_malicious_payload = base64.b64encode(malicious_payload).decode('utf-8')
    print(f"Generated malicious payload (base64): {base64_malicious_payload}")
    process_serialized_data(base64_malicious_payload)

    # OS Command Injection
    print("\n--- Testing OS Command Injection ---")
    safe_input = "my_file.txt"
    execute_command_vulnerable(safe_input)

    # Malicious input example (Trivy won't run this, but it shows the vulnerability)
    # Be CAREFUL if you ever run this locally:
    # malicious_input = "; echo 'PWNED!' > /tmp/pwned.txt"
    # execute_command_vulnerable(malicious_input)

    print("\n--- Vulnerable functions execution complete ---")
