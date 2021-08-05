import socket
import sys
from diffie_hellman import diffie_hellman_des
from des import DesKey

def run(nomeServidor,port,dados):
    
    try: 
        registerDNS = socket.gethostbyname(nomeServidor)
        print(registerDNS,nomeServidor)
        if registerDNS == None:
            raise Exception("Servidor não encontrado")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((registerDNS,port))
            s.sendall('init'.encode('utf-8'))
            data = s.recv(1024)

            diffie_hellman_des_obj = diffie_hellman_des(data.split(';')[1], data.split(';')[2])
            random_num = diffie_hellman_des_obj.generate_random_natural_number(4000, 8000)
            local_mix = diffie_hellman_des_obj.calculate_primary_mix(random_num)
            answer = local_mix

            private_key = diffie_hellman_des_obj.calculate_private_key(
                            data.split(';')[0],
                            random_num
            )

            print("Private key on client is " + private_key)
            private_key_obj = DesKey(bytes(private_key, "utf-8"))

            s.sendall(dados.encode('utf-8'))

    except Exception as e :
        print(e)



if __name__ == '__main__':

    try:
        if len(sys.argv) == 4:
            run(sys.argv[1],int(sys.argv[2]),sys.argv[3])
        else:
            raise Exception("Uso correto: client <nome-servidor> <porta> <dados>")
    except Exception as e:
        print(e)
