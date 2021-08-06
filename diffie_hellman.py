#--------------------------------------------------------------------------------------
#  Programa que implementa o Server
#  Autores: Alejandro Gemin Rosales e Lucas Sidnei dos Santos
#  Disciplina: Redes II
#  Data da ultima atualizacao: 05/08/21
#--------------------------------------------------------------------------------------

import random

class diffie_hellman_des:
    '''
    
        Essa classe define os parametros e funcionalidades que 
        são nessarias para implementar as troca de chave secreta

    '''
    def __init__(self, p, g):

        self.p = p
        self.g = g

    def generate_random_natural_number(self, min_value, max_value):

        return random.randint(min_value, max_value)

    def calculate_primary_mix(self, random_num):

        result = pow(self.g, random_num) % self.p

        return result

    def calculate_private_key(self, external_mix, local_random_num):

        result = str(pow(external_mix, local_random_num) % self.p)

        if len(result) % 8 != 0:
            result = result + "0" * (8 - (len(result) % 8))

        return result