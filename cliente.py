#--------------------------------------------------------------------------------------
#  Programa que implementa o Cliente
#  Autores: Alejandro Gemin Rosales e Lucas Sidneo dos Santos
#  Disciplina: Redes II
#  Data da ultima atualizacao: 05/08/21
#--------------------------------------------------------------------------------------

import socket
import sys
from diffie_hellman import diffie_hellman_des
from des import DesKey


def run(nomeServidor,port,dados):
    
    '''
        Essa função tem como finalidade de enviar algum dado entrado pelo usuário ao servidor.
        A função possui 3 parametros, sendo eles:
        
            nomeServidor -> o nome do servidor (DNS)
            port -> a porta que vai ser utilizada
            dados -> os dados que o cliente que enviar para o servidor


        Após a função ser chamada ela realiza um busca para host_name com a função gethostbyname,
        logo em seguida é aberto o socket por onde realiza as requisições para troca da chave secreta.

        Assim efetuará a conexão com o banco, e enviará uma mensagem para iniciar o processo de troca
        da chave.

        Finalizando realiza a criptografia com base na chave definida e envia para o servidor os 
        dados que o usuário entrou. 
    '''

    try: 

        print('[+] Requisitando host by name')
        registerDNS = socket.gethostbyname(nomeServidor)
      
        if registerDNS == None:
            raise Exception("Servidor não encontrado")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print('[+] Conectando com o servidor {%s} na porta {%d}' % ( registerDNS,port))
            s.connect((registerDNS,port))
            print('[+] Faz requisição para iniciar troca de chave')
            s.sendall('init'.encode('utf-8'))
            data = s.recv(1024)

            print('[+] Gera dados da chave secreta')
            diffie_hellman_des_obj = diffie_hellman_des(int(data.decode('utf-8').split(';')[1]), int(data.decode('utf-8').split(';')[2]))
            random_num = diffie_hellman_des_obj.generate_random_natural_number(4000, 8000)
            local_mix = diffie_hellman_des_obj.calculate_primary_mix(random_num)
            answer = local_mix

            private_key = diffie_hellman_des_obj.calculate_private_key(
                            int(data.decode('utf-8').split(';')[0]),
                            random_num
            )

            private_key_obj = DesKey(bytes(private_key, "utf-8"))
            
            print('[+] Chave secreta gerada com sucesso')
            s.sendall(bytes(str(answer),'utf-8'))

            rest = len(dados)%8
            user_input = dados
            if rest != 0:
                user_input = dados+' '*(8-rest)
           
            cripted_input = private_key_obj.encrypt(bytes(user_input,'utf-8'))
            
            print('[+] Enviando dados do usuario')
            s.sendall(cripted_input.hex().encode('utf-8'))
            print('[+] Mensagem {%s} enviada com sucesso !' %dados)


    except Exception as e :
        print(e)



def main():

    '''
        A função main tem como objetivo chamar a função que envia a mensagem ao servidor.
        Nessa função é verificado se os parametros são todos passados, assim chamando a função principal 
    '''
        
    try:
        if len(sys.argv) == 4:
            run(sys.argv[1],int(sys.argv[2]),sys.argv[3])
        else:
            raise Exception("Uso correto: client <nome-servidor> <porta> <dados>")
    except Exception as e:
        print(e)


main()