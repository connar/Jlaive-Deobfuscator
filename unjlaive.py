from base64 import b64decode
from Crypto.Cipher import AES
import re
from os.path import realpath, dirname, join
import gzip
import pefile

import clr
clr.AddReference("System.Reflection")
clr.AddReference("System")
from System.IO import StreamReader
clr.AddReference("System.IO")
from System.Reflection import Assembly

current_directory = dirname(realpath(__file__))
file_ = dirname(realpath(__file__))
dnlib_ = join(current_directory, "dnlib-4.4.0/src/bin/Debug/net45/dnlib.dll")
clr.AddReference(dnlib_)
import dnlib


def find_main_method(module):
    for t in module.Types:
        for m in t.Methods:
            if m.Name == "Main" and m.IsStatic and m.HasBody:
                return m
    return None

def parse_dotnet():
    # Path to your .NET executable
    exe_path = absolute_path_of_assembly

    # Load the .NET executable using dnlib
    try:
        module = dnlib.DotNet.ModuleDefMD.Load(exe_path)
    except Exception as e:
        print(f"Error loading module: {e}")
        return

    # Find the Main method
    main_method = find_main_method(module)
    all_ldstr = []
    if main_method:
        print(f"[+] Main method found:")
        print(f"\t[*] Module: {module.Name}")
        print(f"\t[*] Method: {main_method.FullName}")
        print(f"[*] Loading instructions of Main...")
        for instr in main_method.Body.Instructions:
            if "ldstr" in str(instr):
                ldstr_stripped = str(instr)[str(instr).index("ldstr ")+len("ldstr "):]
                all_ldstr.append(ldstr_stripped)
    else:
        print("Main method not found.")

    return all_ldstr[-2], all_ldstr[-1]


def extract_embedded_resource(assembly_path, resource_name, output_file):
    try:
        # Load the assembly from the specified path
        assembly = Assembly.LoadFile(assembly_path)

        # Get all the embedded resources within the loaded assembly
        for resource in assembly.GetManifestResourceNames():
            if resource == resource_name:
                # Open the embedded resource stream
                resourceStream = assembly.GetManifestResourceStream(resource)

                if resourceStream is not None:
                    try:
                        # Read the content of the resource
                        streamReader = StreamReader(resourceStream)
                        content = streamReader.ReadToEnd()
                        

                        # Optionally, write the content to an output file
                        with open(output_file, "w") as f:
                            f.write(content)
                            print(f"[*] Resource '{resource_name}' extracted to '{output_file}'")
                            return content # Exit function after extracting the resource
                    finally:
                        # Ensure the stream is closed
                        resourceStream.Close()

        # If resource is not found
        print(f"Resource '{resource_name}' not found in the assembly.")
    except Exception as e:
        print(f"Error extracting resource: {e}")

def decrypt_aes_cbc_and_decompress(encrypted_text, key, iv):
    # Decode the Base64-encoded encrypted text
    encrypted_bytes = encrypted_text

    # Create an AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_bytes)

    # Strip padding
    decrypted_data = _strip_pkcs7_padding(decrypted_data)

    # Decompress the decrypted data using gzip
    decompressed_data = gzip.decompress(decrypted_data)

    return decompressed_data

def _strip_pkcs7_padding(data):
    # Strip PKCS#7 padding from the decrypted data
    padding_length = data[-1]
    return data[:-padding_length]


def replace_text_in_file(input_filename, output_filename, to_be_replaced, to_replace_with):
    # Read the content of the input file
    with open(input_filename, 'r') as input_file:
        file_content = input_file.read()

    # Perform the replacement
    modified_content = file_content.replace(to_be_replaced, to_replace_with)

    # Write the modified content to the output file
    with open(output_filename, 'w') as output_file:
        output_file.write(modified_content)

def write_non_set_lines_to_file(filename, output_filename, deobfed):
    concatenated_values = []

    # Define a regex pattern to match concatenated lines
    concat_pattern = r'%([^%]+)%'  # Match patterns like %variable%

    # Open the file for reading
    with open(filename, 'r') as file:
        # Open the new file for writing non-'set' lines
        with open(output_filename, 'w') as output_file:
            # Read each line in the file
            for line in file:
                # Strip whitespace from the line
                line = line.strip()

                # Check if the line is a concatenated line
                if re.match(concat_pattern, line):
                    concatenated_values.append(line)
                    continue

                if not line.startswith('set '):
                    if line.startswith('attrib -s'):
                        extra = "".join(concatenated_values)
                        output_file.write(extra + '\n' + line + '\n')
                    else:
                        output_file.write(line + '\n')

    return "".join(concatenated_values)

def parse_set_commands(filename):
    variable_declarations = []
    concatenated_values = []

    # Define a regex pattern to match set commands and concatenated lines
    set_pattern = r'^set "(?P<var_name>[^=]+)=(?P<var_value>.*)"'
    concat_pattern = r'%([^%]+)%'  # Match patterns like %variable%

    # Open the file and process each line
    with open(filename, 'r') as file:
        # Read the entire file content
        file_content = file.read()

        # Split the file content into lines based on both newline characters (\n) and && separators
        lines = re.split(r'\n|&&', file_content)

        for line in lines:
            # Strip whitespace from the line
            line = line.strip()
            

            # Check if the line is a concatenated line
            if re.match(concat_pattern, line):
                line = line.replace('%%', '+').replace('%', '')
                # Replace %variable% with variable content
                substituted_line = re.sub(concat_pattern, lambda m: m.group(1), line)
                concatenated_values.append(substituted_line)
            else:
                # Match the line against the set command pattern
                match = re.match(set_pattern, line)
                if match:
                    var_name = match.group('var_name')
                    var_value = match.group('var_value')

                    var_value = var_value.replace("'", '"')

                    # Prepare the Python variable declaration
                    variable_declaration = f"{var_name} = '{var_value}'"
                    variable_declarations.append(variable_declaration)

    return variable_declarations, concatenated_values, line

# Example usage:
filename = './obfuscated.bat'
declarations, concatenated_values, encrypted = parse_set_commands(filename)

# Print out the generated Python variable declarations
for declaration in declarations:
    exec(declaration)


# Initialize an empty string for concatenation
deobfuscated = ""

# Iterate through each concatenated value
for value in concatenated_values:
    # Split the value on '+' to get individual parts
    parts = value.split('+')

    # Add the parts together
    result = ""
    for part in parts:
        result += part + "+"

    # Append the result to the deobfuscated string
    deobfuscated += result

deobfuscated = deobfuscated[:-1]
deobfed = eval(deobfuscated)


input_filename = './obfuscated.bat'
output_filename_tmp = './tmp_Jlaive.ps1'

concatenated_values = write_non_set_lines_to_file(input_filename, output_filename_tmp, deobfed)

print("[*] Sample deobfuscated successfully. Writting result to cleared_Jlaive.ps1")
final_output = 'cleared_Jlaive.ps1'
replace_text_in_file(output_filename_tmp, final_output, concatenated_values, deobfed)

# Define regex pattern to extract Base64-encoded strings
base64_pattern = r'FromBase64String\("([^"]+)"\)'

# Find all matches of Base64 strings in the text
base64_matches = re.findall(base64_pattern, deobfed)

# Extract and decode the Base64 strings to get key and IV
if len(base64_matches) >= 2:
    key_b64 = base64_matches[1]
    iv_b64 = base64_matches[2]

    key = b64decode(key_b64.encode())
    iv = b64decode(iv_b64.encode())
    print(f"[*] Extracted Key: {key_b64}")
    print(f"[*] Extracted IV: {iv_b64}")
else:
    print("Key and IV could not be extracted.")

pattern = r'FromBase64String\("([^"]+)"\)'
matches = re.findall(pattern, deobfed)
if matches:
    b64_extracted = matches[0]

    print("[*] Extracted the wzpaloqi.0.cs file. Writting to wzpaloqi.0.cs")
    with open("./wzpaloqi.0.cs", "wb") as ps:
        ps.write(b64decode(b64_extracted.encode()))
    ps.close()
else:
    print("Could not extract the wzpaloqi.0.cs file.")


enc_decoded = b64decode(encrypted.encode())
loader_stub = decrypt_aes_cbc_and_decompress(enc_decoded, key, iv)
print("[*] Extracting and decrypting the loader_stub. Writting result to loader_stub.exe")

with open("./loader_stub.exe", "wb") as l:
    l.write(loader_stub)
l.close()


print("[*] Parsing loader_stub.exe to decrypt the final executable...")

absolute_path_of_assembly = join(current_directory, "loader_stub.exe")
resource_name = "payload.txt"
output_file = "payload_extracted.txt"
payload_txt = extract_embedded_resource(absolute_path_of_assembly , resource_name, output_file)


key_, iv_ = parse_dotnet()
print(f"[*] Key found: {key_}")
print(f"[*] IV found: {iv_}")

decrypted = decrypt_aes_cbc_and_decompress(b64decode(payload_txt), b64decode(key_), b64decode(iv_))
print("[*] Original executable recovered successfully. Writing to 'target_exe.exe'...")
with open("./target_exe.exe", "wb") as fnl:
    fnl.write(decrypted)
