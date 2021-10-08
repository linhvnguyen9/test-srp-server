import srp


# val = input("Enter your value: ")
# print(val + '|')

# Consider enabling RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
# pysrp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
# uname = input("Username: ")
# password = input("Password: ")

uname = 'linh'
password = '12345678'

saltStr = input("Salt: ")
vkeyStr = input("VKey: ")
salt = bytes.fromhex(saltStr)
vkey = bytes.fromhex(vkeyStr)

# salt, vkey = srp.create_salted_verification_key(uname, password)


class AuthenticationFailed(Exception):
    pass


# ~~~ Begin Authentication ~~~
# print(vkey)
# print(salt)
# vkey_int = list(bytearray(vkey))
# salt_int = list(bytearray(salt))
# print(vkey_int)
# print(salt_int)
# print(bytes(vkey_int).hex())
# print(bytes(salt_int).hex())

usr = srp.User(uname, password)
# uname, A = usr.start_authentication()

AStr = input("A: ")
A = bytes.fromhex(AStr)

# The authentication process can fail at each step from this
# point on. To comply with the SRP protocol, the authentication
# process should be aborted on the first failure.

# Client => Server: username, A
svr = srp.Verifier(uname, salt, vkey, A)
s, B = svr.get_challenge()

print(B.hex())
print(A.hex())

if s is None or B is None:
    raise AuthenticationFailed()

# Server => Client: s, B
MStr = input("M: ")
M = bytes.fromhex(MStr)

if M is None:
    raise AuthenticationFailed()

print(M.hex())

# Client => Server: M
HAMK = svr.verify_session(M)

if HAMK is None:
    raise AuthenticationFailed()

# Server => Client: HAMK
usr.verify_session(HAMK)

# At this point the authentication process is complete.

# assert usr.authenticated()
assert svr.authenticated()
