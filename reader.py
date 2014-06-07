import subprocess

def getCommands(command):
  lines = ""
  output = ""
  solver = subprocess.Popen(
      command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
  
  output += solver.communicate(lines)[0]
  while solver.poll():
		output += solver.communicate()[0]
  return output

def py_get_device_UUID():
	return 'uuid'

def py_get_public_key():
	return 'key'

def py_get_signed_nonce(nonce):
	return getCommands(["./get-signature", "%s" % nonce])

print 'NFC Reader'

# print getCommands("./get-public-key")
# print '------'
# print getCommands("./get-uuid")
# print '------'

nonce = 'abcd'
print py_get_signed_nonce(nonce)

