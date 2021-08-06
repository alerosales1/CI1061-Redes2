#--------------------------------------------------------------------------------------
#  Programa que implementa o Server
#  Autores: Alejandro Gemin Rosales e Lucas Sidnei dos Santos
#  Disciplina: Redes II
#  Data da ultima atualizacao: 05/08/21
#--------------------------------------------------------------------------------------

import socket 
import sys
from diffie_hellman import diffie_hellman_des
from des import DesKey
import codecs

class Connection:

    '''
       Essa classe permite com que grave as informações  
    '''

    private_key = 0
    port_exit = 0
    crypto_obj = 0
    local_mix = 0
    local_random_num = 0

    is_private_key_ready = False

    def __init__(self, ip_orgn, prt_ext):

        self.ip_origin = ip_orgn
        self.port_exit = prt_ext


class MyServer():

    #dic to store already known clients
    clients = {}
    __diffie_hellman_des = diffie_hellman_des(23,5)

    def run(self,port):

        hostName = socket.gethostname()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((hostName, port))
            s.listen()

            print("Servidor %s rodando na porta %d" % (hostName,port))
            while True:
                conn, addr = s.accept()
                with conn:
                    # print('Connected by', addr)
                    while True:
                        data = conn.recv(1024)
                        answer = ""
                        
                        if data.decode() == 'init' and not addr in self.clients:
                            
                            self.clients[addr] = Connection(addr, 0)

                            p = self.__diffie_hellman_des.p
                            g = self.__diffie_hellman_des.g

                            random_num = self.__diffie_hellman_des.generate_random_natural_number(100, 1000)
                            self.clients[ addr ].local_random_num = random_num
                            mix = self.__diffie_hellman_des.calculate_primary_mix(random_num)
                            self.clients[ addr ].local_mix = mix
                            answer = str(mix)+';'+ str(p) +';'+ str(g)
                            conn.sendall(bytes(answer,'utf-8'))
                            

                        elif self.clients[addr].is_private_key_ready:
                           
                            if len(data.decode('utf-8')) > 0:
                                message = self.clients[addr].private_key.decrypt(bytes.fromhex(data.decode('utf-8')))
                                print("Sou servidor %s, recebi a mensagem %s" % (hostName,codecs.decode(message)))
                                break
                        else:
                           
                            private_key = self.__diffie_hellman_des.calculate_private_key(int(data.decode('utf-8').split(';')[0]),
                                                                    self.clients[addr].local_random_num)

                            self.clients[addr].private_key = DesKey(bytes(private_key, "utf-8"))
                            self.clients[addr].is_private_key_ready = True

                            # print("Private key on server is " + private_key)


if __name__ == "__main__":

    try:
        if len(sys.argv) == 2 :
            MyServer.run(MyServer,int(sys.argv[1]))
        else:
            raise Exception("Uso correto: servidor <porta>")

    except Exception as e:
        print(e)