#--------------------------------------------------------------------------------------
#  Programa que implementa o Server
#  Autor: Alejandro Gemin Rosales e Lucas Santos
#  Disciplina: Redes II
#  Data da ultima atualizacao: 05/08/21
#--------------------------------------------------------------------------------------
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import codecs
from des import DesKey
from diffie_hellman import diffie_hellman_des
import pickle

hostName = "localhost"
serverPort = 31364

#object to store connection information
class Connection:

    private_key = 0
    port_exit = 0
    crypto_obj = 0
    local_mix = 0
    local_random_num = 0

    is_private_key_ready = False

    def __init__(self, ip_orgn, prt_ext):

        self.ip_origin = ip_orgn
        self.port_exit = prt_ext


class MyServer(BaseHTTPRequestHandler):

    #dic to store already known clients
    clients = {}
    __diffie_hellman_des = diffie_hellman_des(23,5)

    #process POST request
    def do_POST(self):

        print("POST request received from IP " + self.client_address[0] + ", and from door " + str(self.client_address[1]))

        #get json object containing parameters like p and g
        content_len = int(self.headers.get('content-length', 0))
        post_body = codecs.decode(self.rfile.read(content_len))
        # print(post_body)

        json_obj = {}

        #parse json file
        try:
            json_obj = json.loads(post_body)
        except:
            json_obj = {}

        answer = ""

        if not self.client_address[0] in self.clients:

            self.clients[self.client_address[0]] = Connection(self.client_address[0], 0)

            p = self.__diffie_hellman_des.p
            g = self.__diffie_hellman_des.g

            random_num = self.__diffie_hellman_des.generate_random_natural_number(100, 1000)

            self.clients[ self.client_address[0] ].local_random_num = random_num

            mix = self.__diffie_hellman_des.calculate_primary_mix(random_num)

            self.clients[ self.client_address[0] ].local_mix = mix

            answer = '{"server_mix":' + str(mix) + ', "p":' + str(p) + ', "g":' + str(g) + '}'

        elif self.clients[self.client_address[0]].is_private_key_ready:

            message = self.clients[self.client_address[0]].private_key.decrypt(bytes.fromhex(json_obj['msg']))

            print("Message from client: " + codecs.decode(message))

        else:

            private_key = self.__diffie_hellman_des.calculate_private_key( json_obj['client_mix'],
                                                    self.clients[self.client_address[0]].local_random_num)

            self.clients[self.client_address[0]].private_key = DesKey(bytes(private_key, "utf-8"))
            self.clients[self.client_address[0]].is_private_key_ready = True

            print("I know this client from " + self.client_address[0])
            print("Private key on server is " + private_key)

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(answer, "utf-8"))

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
