#--------------------------------------------------------------------------------------
#  Programa que implementa o Cliente
#  Autores: Alejandro Gemin Rosales e Lucas Santos
#  Disciplina: Redes II
#  Data da ultima atualizacao: 05/08/21
#--------------------------------------------------------------------------------------
import codecs
import json

import requests
from des import DesKey
from diffie_hellman import diffie_hellman_des
import pickle

server_url = 'http://localhost:31364/match'

x = requests.post(server_url)

print(x.text)
print(x.status_code)

json_msg = bytes(x.text, 'utf-8')
json_obj = json.loads(json_msg)

diffie_hellman_des_obj = diffie_hellman_des(json_obj['p'], json_obj['g'])

random_num = diffie_hellman_des_obj.generate_random_natural_number(4000, 8000)

local_mix = diffie_hellman_des_obj.calculate_primary_mix(random_num)

answer = {"client_mix":local_mix}

private_key = diffie_hellman_des_obj.calculate_private_key(

                json_obj['server_mix'],
                random_num

                                       )

print("Private key on client is " + private_key)

private_key_obj = DesKey(bytes(private_key, "utf-8"))

x = requests.post(server_url, json = answer)

user_input = ""

while user_input != "exit":

    user_input = input("Message to server: ")

    rest = len(user_input) % 8
    if rest != 0:
        user_input = user_input + " " * (8 - rest)

    crypted_input = private_key_obj.encrypt(bytes(user_input, 'utf-8'))

    answer = {"msg": crypted_input.hex()}

    x = requests.post(server_url, json = answer)
