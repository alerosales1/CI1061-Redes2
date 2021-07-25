# --------------------------------------------------------------------------------------
#   Programa que implementa o servidor
#   Objetivo: implementar um servidor em linguagem python3
#   Restricoes: -

#   Autores: Alejandro G. Rosales e Lucas Santos
#   Disciplina: Redes II
#   Data da ultima atualizacao: 24/07/2021
#----------------------------------------------------------------------------------------#

#!/usr/bin/env pyhton3

import socket
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import codecs
from des import DesKey

HOST  = 'localhost'
PORTA = 31364

#objeto para armazenar informações de conexão
class Connection:

    private_key = 0
    port_exit   = 0
    obj_crypto  = 0
    local_mix   = 0
    local_random_num = 0
    g = 0 #num primo Diffie–Hellman
    p = 0 #base Diffie–Hellman
    
    chave_privada_pronta = False

    def __init__(self, ip_origin, prt_ext):

        self.ip_origin = ip_origin
        self.port_exit = prt_ext

class MyServer(BaseHTTPRequestHandler):
    
    #dic para armazenar clients ja prontos
    clients = {}

    def __generate_random_natural_number(self, max_value, min_value):
        return random.randint(min_value, max_value)
    
    
    def __calculate_primary_mix(self,g,p,random_num):
        result = pow(g,random_num) % p
        return result

    def __calculate_private_key(self, external_mix, local_random_num, p):
        result = str(pow(external_mix,local_random_num) % p)

        if len(result) % 8 != 0:
            result = result + "0" * (8 - (len(result) % 8))

        return result    

        #processa solicitação
    def do_POST(self):

        print(self.client_address)

        #obter objeto json contendo parâmetros como p e g
        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        self.wfile.write(bytes("received post request:<br>{}".format(post_body), "utf-8"))

        #analisar arquivo json
        json_obj = json.loads(post_body)

        answer = ""

        if not self.client_address[0] in self.clients:

            self.clients[self.client_address[0]] = Connection(self.client_address[0], 0)

            self.clients[self.client_address[0]].p = json_obj['p']
            self.clients[self.client_address[0]].g = json_obj['g']

            random_num = self.__generate_random_natural_number(100, 1000)

            self.clients[ self.client_address[0] ].local_random_num = random_num

            mix = self.__calculate_primary_mix(json_obj['g'], json_obj['p'], random_num)

            self.clients[self.client_address[0]].local_mix = mix

            answer = '{"server_mix":' + mix + '}'

        elif self.clients[self.client_address[0]].is_private_key_ready:

            msg_binary = bytes(json_obj['msg'], "utf-8")

            message = self.clients[self.client_address[0]].private_key.decrypt(msg_binary)

            print(codecs.decode(message))

        else:

            private_key = self.__calculate_private_key(

                self.clients[self.client_address[0]].local_mix,
                self.clients[self.client_address[0]].random_num,
                self.clients[self.client_address[0]].p

                                                       )

            self.clients[self.client_address[0]].private_key = DesKey(bytes(private_key, "utf-8"))
            self.clients[self.client_address[0]].is_private_key_ready = True

            print("I know this client")
            print(self.client_address[0])

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(answer, "utf-8"))

if __name__ == "__main__":
    webServer = HTTPServer((HOST, PORTA), MyServer)
    print("Server started http://%s:%s" % (HOST, PORTA))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")

