import binascii
import os
import logging
import subprocess
from subprocess import Popen
import tempfile
import time
import uuid

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class KeytabManager:
    def __init__(self):
        self.temp_files = []

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self._cleanup_temp_files()

    def generate_random_keytab_file_path(self):
        """
        Generates a random file path in the /tmp directory and adds the
        file path to a local collection of all generated file paths
        Returns:
            Randomly generated file path
        """
        filepath = os.path.join("/tmp", uuid.uuid4().hex)
        self._track_temp_file(filepath)
        return filepath

    def _track_temp_file(self, filepath: str):
        """
        Adds a file path to a local data structure.
        Args:
            filepath (string): File path to track
        """
        self.temp_files.append(filepath)

    def _cleanup_temp_files(self):
        for file in self.temp_files:
            try:
                os.remove(file)
            except OSError:
                pass

    def split_keytab(self, master_keytab_data: bytes, principals: list, user_principal: str) -> str:
        """
        Splits a keytab by filtering out any unspecified principals.
        If no principals are specified, no filtering is done.
        Args:
            master_keytab_data (bytes): Binary format of the keytab containing all principals for the user
            principals (list): Principals to preserve from the original keytab
            user_principal (string): User principal that the keytab authenticates
        Returns:
            keytab_data (bytes): A binary encoded keytab
        Raises:
            Exception: If keytab fails to split
        """
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as temp_keytab_file:
            temp_keytab_file.write(master_keytab_data)
            temp_keytab_file.flush()
            try:
                # Generate a new keytab containing keys for all principals specified.
                # If no principals are specified, a keytab containing all principals'
                # keys will be generated.
                new_keytab_data = self._create_new_keytab_from_principals(temp_keytab_file.name,
                                                                          principals,
                                                                          user_principal)
                base64_encoded_keytab = KeytabManager.binary_to_base64_string(new_keytab_data)
                return base64_encoded_keytab
            except Exception as e:
                raise Exception(f"Failed to split keytab: {e}")

    def generate_new_keytab_file(self, username: str, password: str, user_principal: str, domain_name: str) -> bytes:
        """
        Generates a new keytab for a given user. The keytab contains all principals belonging to the user.
        Args:
            username (string): AD user name
            password (string): Password of the AD user
            user_principal (string): User principal of the AD user and the domain it belongs to
            domain_name (string): Domain or directory name
        Returns:
            keytab_data (string): A binary encoded keytab
        Raises:
            Exception: If keytab fails to create or validate
        """
        try:
            output_filepath = self.generate_random_keytab_file_path()
            generate_keytab_command = [
                "./msktutil",
                "update",
                "--use-service-account",
                "--account-name",
                username,
                "--old-account-password",
                password,
                "--keytab",
                output_filepath,
                "--dont-change-password",
                "--realm",
                domain_name.upper(),
                "-N"
            ]
            KeytabManager._run_command(command=generate_keytab_command)
            keytab_data = KeytabManager._read_file_as_bytes(output_filepath)
            KeytabManager._validate_keytab(keytab_data, user_principal)
            return keytab_data
        except Exception as e:
            raise Exception(f"Keytab failed to create or validate: {e}")

    @staticmethod
    def validate_base64_encoded_keytab(base64_encoded_keytab: str, user_principal: str):
        """
        Validates a base64 encoded keytab
        Args:
            base64_encoded_keytab (string): Base64 encoded keytab data
            user_principal (string): User principal that the keytab authenticates
        Raises:
            ValueError: If base64 encoded keytab fails to validate
        """
        try:
            # Decode keytab back to binary form
            binary_keytab_data = KeytabManager.base64_string_to_binary(base64_encoded_keytab)

            # Validate binary keytab data
            KeytabManager._validate_keytab(binary_keytab_data, user_principal)
        except ValueError as e:
            raise ValueError(f"Failed to validate base64 encoded keytab: {e}")

    @staticmethod
    def _validate_keytab(binary_keytab_data: bytes, user_principal: str):
        """
        Validates a keytab against a user principal using kinit
        Args:
            binary_keytab_data (bytes): Binary data of keytab to validate
            user_principal (string): User principal to validate against
        Raises:
            ValueError: If keytab validation fails
        """
        try:
            # Write binary keytab data to file (kinit is used to validate the keytab, and kinit only handles files)
            with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as temp_keytab_file:
                temp_keytab_file.write(binary_keytab_data)
                temp_keytab_file.flush()

                # Validate using kinit
                with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as cache:
                    kinit_command = [
                        "./kinit",
                        "-c",
                        cache.name,
                        user_principal,
                        "-k",
                        "-t",
                        temp_keytab_file.name
                    ]
                    KeytabManager._run_command(kinit_command)
        except ValueError as e:
            raise ValueError(f"Keytab validation failed: {e}")

    def _create_new_keytab_from_principals(self,
                                           original_keytab_filepath: str,
                                           principals: list,
                                           user_principal: str) -> bytes:
        """
        Create a new keytab containing a subset of principals from an
        existing keytab
        Args:
            original_keytab_filepath (string): Path to an existing keytab
            principals (list): Principals to include in the new keytab
            user_principal (string): User principal associated with the keytabs
        Raises:
            Exception: If new keytab fails to create or validate
        """
        try:
            # If no principals are specified, a keytab with all principals will
            # be created by default
            if not principals:
                logger.warning(f"No principals specified. Creating a new keytab for all SPNs under UPN {user_principal}")
                keytab_data = KeytabManager._read_file_as_bytes(original_keytab_filepath)
                return keytab_data

            #
            # If principals are specified, a new keytab is generated by starting with a comprehensive
            # keytab and deleting the principals that were not specified.
            #

            # In keytab file, principals are ordered and given an order number.
            # The order number is known as a "slot". This call will retrieve a
            # map of each principal and its given slot number.
            principal_slots = KeytabManager._get_principal_slots(original_keytab_filepath)

            # Get slot numbers of principals to delete
            slot_numbers_to_delete = KeytabManager._get_slot_numbers_to_delete(principals, principal_slots)

            # Generate staging file path for new keytab
            new_keytab_filepath = self.generate_random_keytab_file_path()

            # Generate list of commands to send to ktutil
            delent_commands = KeytabManager._get_delent_commands_from_slots(slot_numbers_to_delete)
            read_kt_command = f"read_kt {original_keytab_filepath}"
            write_kt_command = f"write_kt {new_keytab_filepath}"
            quit_command = "quit"
            ktutil_commands = [
                read_kt_command,
                *delent_commands,
                write_kt_command,
                quit_command
            ]

            # Create keytab from subset of principals
            ktutil_interactive = InteractiveCommand("./ktutil", ktutil_commands)
            ktutil_interactive.send_commands()

            # Validate the new keytab using kinit
            new_keytab_data = KeytabManager._read_file_as_bytes(new_keytab_filepath)
            KeytabManager._validate_keytab(new_keytab_data, user_principal)

            return new_keytab_data
        except Exception as e:
            raise Exception(f"Failed to create or validate new keytab from principals: {e}")

    def get_principals_from_base64_keytab(self, base64_encoded_keytab: str) -> set:
        binary_encoded_keytab = KeytabManager.base64_string_to_binary(base64_encoded_keytab)
        return self._get_principals_from_binary_keytab(binary_encoded_keytab)

    def _get_principals_from_binary_keytab(self, binary_keytab_data: bytes) -> set:
        with tempfile.NamedTemporaryFile(dir="/tmp", delete=True) as temp_keytab_file:
            temp_keytab_file.write(binary_keytab_data)
            temp_keytab_file.flush()
            principal_slots = self._get_principal_slots(temp_keytab_file.name)
            return set(principal_slots.values())

    @staticmethod
    def _get_slot_numbers_to_delete(principals_to_keep: list, principal_slots: dict):
        """
        Identify the slot numbers to delete based on a list of principals to keep.
        Args:
            principals_to_keep (list): List of principals to keep
            principal_slots (dict): Dict of principals mapped to their slot numbers
        Returns:
            to_delete (list): A list of slot numbers to delete
        """
        to_delete = []
        for slot_number, principal in principal_slots.items():
            if principal not in principals_to_keep:
                to_delete.append(slot_number)
        return to_delete

    @staticmethod
    def _get_principal_slots(keytab_filepath: str) -> dict:
        """
        Get slot numbers (index) of each keytab principal in a keytab
        Args:
            keytab_filepath (string): Keytab to get slot numbers for
        Returns:
            slots (dict): A dictionary of a keytab's principals mapped to their
            respective slot number
        """
        try:
            # Print out principals in keytab, then split the output into lines
            klist_command = ['./klist', '-k', keytab_filepath]
            klist_output = KeytabManager._run_command(command=klist_command)
            lines = klist_output.splitlines()

            # Principal listings begin on the 4th line
            principal_lines = lines[3:]

            # Each line is space-delimited and the last entry is the principal.
            # Save every principal and preserve their order
            principals = [line.split(" ")[-1] for line in principal_lines]

            # Assign slot numbers to each principal, starting with 1
            slots = zip(range(1, len(principals) + 1), principals)
            slots = {slot[0]: slot[1] for slot in slots}

            # Return each principal with its assigned slot number
            return slots
        except ValueError as e:
            raise ValueError(f"Failed to get principal slots: {e}")

    @staticmethod
    def _get_delent_commands_from_slots(slots_to_delete: list) -> list:
        """
        Convert list of slots to delete into a list of commands to pipe
        into ktutil. Slots deletion is put in reverse order.
        Args:
            slots_to_delete (list): Keytab principal slots to delete from a keytab
        Returns:
            A list of "delent" commands for ktutil
        """
        # Principals must be deleted in reverse order because ktutil resets the slot numbers
        # when a principal is deleted (e.g. if we delete principal in slot 1, indexing resets
        # such that principal in slot 2 moves to slot 1, etc. Every slot number is decreased by 1).
        slots_to_delete = sorted(slots_to_delete)
        slots_to_delete.reverse()

        return [f"delent {slot}" for slot in slots_to_delete]

    @staticmethod
    def _run_command(command: list, timeout_in_seconds: int = 15) -> str:
        """
        Runs a command line command using subprocess.
        Args:
            command (list): Command to execute from context of a command line
            timeout_in_seconds (int): Timeout for command execution
        Returns:
            output (string): Standard out from command execution
        Raises:
            ValueError: If the command execution throws an error
        """
        proc = subprocess.Popen(command,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                encoding="utf-8",
                                shell=False)
        output, error = proc.communicate(timeout=timeout_in_seconds)
        if error or proc.returncode != 0:
            raise ValueError(
                "Subprocess command failed: %d %s %s" % (proc.returncode, error, output)
            )
        return output

    @staticmethod
    def _read_file_as_bytes(filepath: str) -> bytes:
        """
        Reads a files contents as bytes
        Args:
            filepath (string): File path to read
        Returns:
            Bytes in file
        """
        try:
            with open(filepath, 'rb') as new_keytab:
                return new_keytab.read()
        except Exception as e:
            logger.info(f"Could not read bytes from file {filepath}: {e}")
            return bytes()

    @staticmethod
    def get_user_principal(user: str, domain_name: str):
        """
        Converts an AD user name and a domain name to a user principal string
        Args:
            user (string): AD user
            domain_name (string): AD domain name or directory name
        Returns:
            AD user principal
        """
        return f"{user}@{domain_name.upper()}"

    @staticmethod
    def binary_to_base64_string(binary_data: bytes) -> str:
        return binascii.b2a_base64(binary_data, newline=False).decode("utf8")

    @staticmethod
    def base64_string_to_binary(base64_str: str) -> bytes:
        return binascii.a2b_base64(base64_str)


class InteractiveCommand:
    def __init__(self, executable: str, commands: list):
        self.executable = executable
        self.commands = commands

    def send_commands(self, expects_response=False):
        """
        Sends multiple commands to an interactive executable

        Returns:
            nothing
        """
        # Start the interactive command in a process
        process = self._start_process()

        # Send the interactive commands
        for command in self.commands:
            self._write(process, command)
            time.sleep(.2)  # Some delay is required for subsequent commands to be properly registered

            if expects_response:
                self._read(process)

        # Terminate the process
        self._terminate(process)

    def _start_process(self):
        """
        Starts a subprocess

        Returns:
            nothing
        """
        return subprocess.Popen(self.executable,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    def _read(self, process: Popen):
        """
        Reads output from the open process

        Args:
            process: current open process

        Returns:
            nothing
        """
        return process.stdout.readline().decode("utf-8").strip()

    def _write(self, process: Popen, command: str):
        """
        Sends commands to the open process

        Args:
            process: current open process
            command: command to send

        Returns:
            nothing
        """
        process.stdin.write(f"{command.strip()}\n".encode("utf-8"))
        process.stdin.flush()

    def _terminate(self, process: Popen):
        """
        Safely terminates the current open process
        Args:
            process: current open process

        Returns:
            nothing
        """
        process.stdin.close()
        process.terminate()
        process.wait(timeout=0.2)
