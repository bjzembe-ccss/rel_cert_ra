import re
import subprocess
import sys

### EDIT THIS ###
# filepath to oqs/apps/openssl executable
OQS_CMD = "/home/ubuntu/public_related_certs/openssl-rel-cert/apps/openssl"
#################

ACCESS_LOCATION = '127.0.0.1:8000'
ACCESS_METHOD = 'id-ad-relatedCerts'
IS_REFERENCE_VERSION = False
VERBOSE = False

def gen_config_file(filepath_cert, filepath_key, server_uri=ACCESS_LOCATION):
  # extrate file path, filename, and extension type
  match = re.search(r'(.*?)([^\/\.]+)\.(.+)', filepath_cert)
  path, filename_cert, ext = [match.group(i) for i in range(1, 4)]

  # extract certificate field content
  issuer = _get_issuer(filepath_cert)
  serial = _get_serial(filepath_cert)
  time = _get_time(filepath_cert)
  signature = _get_signature(filepath_cert, filepath_key, time, issuer, serial)
  access_location = server_uri

  # build fields for config file
  cert_id = _create_issuer_and_serial_number(issuer, serial)
  location_info = _create_access_description(ACCESS_METHOD, access_location)

  # create config file
  requester_certificate = _create_requester_certificate(cert_id, time, location_info, signature)

  #  write config file
  _write_config(requester_certificate, filename_cert)

  print('completed.')
  return

def _create_issuer_and_serial_number(issuer, serial):
  if IS_REFERENCE_VERSION:
    contents = "[ certID ]\n"
    contents += "issuer=" + str(issuer) + "\n"
    contents += "serial=" + str(serial)
  else:
    contents = "certID="
    contents += "issuer='" + str(issuer) + "', "
    contents += "serial=" + str(serial)

  return contents

def _create_access_description(access_method, access_location):
  if IS_REFERENCE_VERSION:
    contents = "[ locationInfo ]\n"
    contents += "accessMethod=" + str(access_method) + "\n"
    contents += "accessLocation=" + str(access_location) + "\n"
  else:
    contents = "locationInfo="
    contents += "accessMethod = " + str(access_method) + ", "
    contents += "accessLocation = " + str(access_location)
    
  return contents

def _create_requester_certificate(cert_id, request_time, location_info, signature):
  if IS_REFERENCE_VERSION:
    contents = "[ rel_cert ]\n"
    contents += "certID = @certID\n"
    contents += "requestTime=" + str(request_time) + "\n"
    contents += "locationInfo=@locationInfo\n"
    contents += "signature=" + str(signature) + "\n\n"

    contents += str(cert_id) + str("\n\n")
    contents += str(location_info) + str("\n\n")
  else:
    contents = "[ rel_cert ]\n"
    contents += str(cert_id) + "\n"
    contents += "requestTime=" + str(request_time) + "\n"
    contents += str(location_info) + "\n"
    contents += "signature=" + str(signature) + "\n\n"

  return contents

def _get_issuer(file):
  cmd = OQS_CMD + " x509 -in " + str(file) + " -noout -issuer"
  process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  if process.returncode:
    _printerror(process.stdout)
    quit()

  issuer = process.stdout
  issuer = str(issuer)[9:-3]
  issuer = issuer.replace(" = ", "=")
  issuer = issuer.replace('"', "")

  return issuer

def _get_serial(file):
  cmd = OQS_CMD + " x509 -in " + str(file) + " -noout -serial"
  process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  if process.returncode:
    _printerror(process.stdout)
    quit()

  serial = process.stdout
  serial = str(serial).split('=')[1][:-3]
  serial = ':'.join([ serial[2*i : 2*i+2] for i in range(0, int(len(serial)/2)) ])

  return serial

def _get_signature(cert_file, key_file, time, issuer, serial):
  #der_iss_and_ser_cmd = str(OQS_CMD) + "x509 -in " + str(file) + " -issuer -serial -outform DER"

  #cmd_oqs = str(OQS_CMD) + " x509 -in " + str(file) + " -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame"
  #cmd_grep = ['grep', '-v', "Signature Algorithm"]
  #cmd_tr = "tr -d '[:space:]' "
  payload = str(time) + issuer + serial
  payload_file = open('tmp_rel_cert.txt', 'w')
  payload_file.write(payload)
  payload_file.close()

  cmd_oqs = str(OQS_CMD) + " dgst -sha256 -hex -c -sign " + key_file + " tmp_rel_cert.txt"
  process = subprocess.run(cmd_oqs.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  if process.returncode:
    _print_error(process.stdout)
    quit()

  signature = str(process.stdout)
  signature = signature[signature.find(' ') + 1:-3]

  return signature

def _get_time(file):
  cmd = "date -r " + str(file) + " +%s"
  process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  if process.returncode:
    _print_error(process.stdout)
    quit()

  time = process.stdout
  time = int(str(time)[2:-3])

  return time

def _print_error(msg, filename='gen_rel_cert_config.py', display_usage=True):
  print(str(msg) + '\n')

  if display_usage:
    print("Usage: python3 " + str(filename) + " CERT_FILEPATH PRIVATE_KEY_FILEPATH SERVER_URI [-v|--verbose]")

def _write_config(contents, filename):
  # create file
  filepath = "config/hybrid_" + str(filename) + ".cnf"
  cmd = "cp config/rel_cert_base.cnf " + filepath
  process = subprocess.run(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  if process.returncode:
    _print_error(process.stdout)
    quit()

  f = open(filepath, 'a')
  f.write(contents)
  f.close()

  return

if __name__ == '__main__':
  args = sys.argv

  if 0 < len(args) < 3:
    _print_error("ERROR: Incorrect Parameters")
    quit()

  if args[-1] in ['v', "--verbose"]:
    VERBOSE = True

  gen_config_file(args[1], args[2])

