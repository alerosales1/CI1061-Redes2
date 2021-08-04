import codecs
from des import DesKey

obj = DesKey(b'12345567')

plain="Ablablqabluea"

rest = len(plain) % 8

print(len(plain))

if rest != 0:
    plain = plain + " "*(8-rest)

print(plain)

ciph = obj.encrypt(bytes(plain, 'utf-8'))

print(ciph)

deciph = obj.decrypt(ciph)

print(codecs.decode(deciph))