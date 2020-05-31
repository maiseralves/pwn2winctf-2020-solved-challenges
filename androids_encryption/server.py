#!/usr/bin/python3 -u
# *-* coding: latin1 -*-
import sys
import base64
from Crypto.Cipher import AES
#from secrets import flag, key1, iv1

# nc encryption.pwn2.win 1337

flag = b'0000000000000000'
key1 = b'0000000000000000'
iv1  = b'0000000000000000'


BUFF = 256
BLOCK_SIZE = 16

# Como resolver o desafio Androids Encryption do CTF pwn2win usando esse script:
# https://pwn2.win/NIZKCTF-js/challenges

# Passos:
# a) Execute: nc encryption.pwn2.win 1337
# b) Escolha: 1 Encypt your txt
# c) Execute: esse script
# d) Escolha: 5 Xor ciphered txt to get key2 (para obter a key2 que é usada para cifrar a flag)
# e) Escolha no server: 2 Encrypt my secret (para obter a flag cifrada com a key2 da opção 1)
# f) Escolha nesse script: 2 Decrypt my secret (que já terá a key2 que foi setada globalmente quando da execução do passo d)
# g) Strike! Capturamos a FLAG -> CTF-BR{kn3W_7h4T_7hEr3_4r3_Pc8C_r3pe471ti0ns?!?}

# Descrição detalhada:
# Primeiro deve se conectar via netcat no server:  nc encryption.pwn2.win 1337
# execute a opção 1 (Encrypt your txt) do server colocando sua mensagem txt em base64
# será gerada a sua mensagem criptografada que é o ctxt (ciphered txt)
# Então execute este script e com a mensagem cifrada ctxt, em mãos, gerada pelo server
# escolha a opção 5 (Xor ciphered txt to get key2) e assim teremos a key2 que é usada pelo server
# Devemos voltar para o netcat do server e escolher a opção (Encrypt my secret) e pasmem! 
# temos o "pulo do gato" desse desafio, a key2 que foi usada para criptografar a flag é o xor(ctxt) da mensagem
# criptografada pela opção 1
# Finalmente executamos a opção 4 do nosso script (Decrypt my secret) e temos através da variável global (key2) que foi setada
# ao fazer o xor(ctxt) da opção 1 do server, diponível no nosso código e decriptando a flag

# Observações:
# Para resolver esse desafio foi necessário implementar a função dec_flag que faz o reverso da função encrypt
# e para isso temos que entender como é criptografada a mensagem na função encrypt (recomenda-se desenhar um diagrama)

# Thanks to BOTDrake (https://ctftime.org/user/6548) and nutcake for your help


# Referencias úteis:
# https://stackoverflow.com/questions/14716338/pycrypto-how-does-the-initialization-vector-work
# https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/
# https://pt.wikipedia.org/wiki/Modo_de_opera%C3%A7%C3%A3o_(criptografia)#Modo_ECB_(Electronic_CodeBook)



# transforma txt em blocos de 16bytes (BLOCK_SIZE) cada um retornando um lista
def to_blocks(txt):
    return [txt[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(txt)//BLOCK_SIZE)]


# realiza a operação de XOR partindo do primeiro bloco na listagem de 'b1' até o último bloco existente
# cada operação de xor é realazada entre o resultado do xor do bloco anterior com o próximo na lista
# e o resultado dessa operação de xor é operado novamente com o próximo bloco da lista
# até acabarem os blocos de 'b1'
# obs: essa função se torna recursiva quando 'b2' é None
# traduzindo:
# bloco1 xor bloco2 => resultado1 xor bloco3 => resultado2 xor bloco4 ....
def xor(b1, b2=None):
    if isinstance(b1, list) and b2 is None:
        assert len(set([len(b) for b in b1])) == 1, 'xor() - Invalid input size'
        assert all([isinstance(b, bytes) for b in b1]), 'xor() - Invalid input type'
        x = [len(b) for b in b1][0]*b'\x00'
        for b in b1:
            x = xor(x, b)
        return x
    assert isinstance(b1, bytes) and isinstance(b2, bytes), 'xor() - Invalid input type'
    return bytes([a ^ b for a, b in zip(b1, b2)])


iv2 = AES.new(key1, AES.MODE_ECB).decrypt(iv1)
# essa chave key2 resulta em um bloco de 16bytes da operação xor entre todos os blocos da flag realizado byte a byte (caracter por caracter)
key2 = xor(to_blocks(flag))


# 1) esta funcao transforma o txt em blocos (#1)
# 2) inicializa o AES em modo ECB com a chave key (#2) e que para opção 1 se torna key1 e para opção 2 se torna key2
# 3) pega o initialization vector iv e faz ele ser o iv current (#3)
# 4) para cada bloco é realizado xor entre o bloco corrente do loop e curr e desse resultado é feito a cifragem com o AES (#4)
# 5) curr que seria o initialization vector em cada iteração é atualizado com a operação xor entre o último bloco cifrado anteriormente
#    e o bloco corrente e que depois é utilizado na próxima iteração como parâmetro da função xor e o novo bloco corrente
# 6) então a chave key2 é usada na inicialização de um novo AES ECB que gera um inicialization vector iv2
# 7) e em seguida key2 se torna o resultado do xor entre os blocos do texto cifrado (ctxt)
# 8) finalmente o iv que é iv1 na opção 1 e iv2 na opção 2 é concatenado ao texto cifrado (ctxt) e transformado em base64
def encrypt(txt, key, iv):
    global key2, iv2
    assert len(key) == BLOCK_SIZE, f'Invalid key size'
    assert len(iv) == BLOCK_SIZE, 'Invalid IV size'
    assert len(txt) % BLOCK_SIZE == 0, 'Invalid plaintext size'
    bs = len(key)
    blocks = to_blocks(txt) # (1)
    ctxt = b''
    aes = AES.new(key, AES.MODE_ECB) # (2)
    curr = iv # (3)

    for block in blocks:
        ctxt += aes.encrypt(xor(block, curr)) # (4)
        curr = xor(ctxt[-bs:], block) # (5)


    iv2 = AES.new(key2, AES.MODE_ECB).decrypt(iv2) # (6)
    key2 = xor(to_blocks(ctxt)) # (7)

    return str(base64.b64encode(iv+ctxt), encoding='utf8') # (8)


# criptografa a flag com a chave key2 e o vetor de inicialização iv2
def enc_flag():
    print(encrypt(flag, key2, iv2))


# decriptografa a flag
def dec_flag():
    print('---> base64 ciphered string: \n', end='')

    txt = base64.b64decode(input().rstrip())

    rescued_iv2 = txt[:16] # pega o iv2 da mensagem base64 decodificada
    rescued_mesg2 = txt[16:] # pega a mensagem base64 decodificada em si

    plaintext = b''
    aes = AES.new(key2, AES.MODE_ECB)

    bs = len(key2)
    curr = rescued_iv2
    blocks = to_blocks(rescued_mesg2)

    flag = b''

    for block in blocks:
        assert set([len(block)]) == {16}, 'bloco com tamanho invalido'
        assert all([isinstance(block, bytes)]), 'tipo do bloco invalido'
        flag += xor(aes.decrypt(block), curr)
        curr = xor(flag[-bs:], block)

    print()
    print('---> Decripted flag: ')
    print(flag)
    print()

# criptografa o texto plano que foi passado em base64 com a chave key1 e iv1
def enc_plaintext():
    
    print('Plaintext: ', end='')

    txt = base64.b64decode(input().rstrip())
    #txt = base64.b64decode('MTIzNDU2Nzg5MDEyMzQ1NjEyMzQ1Njc4OTAxMjM0NTY=')

    print()
    print(encrypt(txt, key1, iv1))

# decriptografa o texto plano usando key1 e ev1
def dec_plaintext():
    print('---> base64 ciphered string: \n', end='')

    txt = base64.b64decode(input().rstrip())

    rescued_iv = txt[:16] # pega o iv da mensagem base64 decodificada
    rescued_mesg = txt[16:] # pega a mensagem base64 decodificada em si

    plaintext = b''
    aes = AES.new(key1, AES.MODE_ECB)

    bs = len(key1)
    curr = rescued_iv
    blocks = to_blocks(rescued_mesg)

    plaintext = b''

    for block in blocks:
        assert set([len(block)]) == {16}, 'bloco com tamanho invalido'
        assert all([isinstance(block, bytes)]), 'tipo do bloco invalido'
        plaintext += xor(aes.decrypt(block), curr)
        curr = xor(plaintext[-bs:], block)

    print()
    print('---> decripted your text: ')
    print(plaintext)
    print()

def dec_base64():
    print('---> decode base64 ciphered string: \n', end='')
    txt = base64.b64decode(input().rstrip())
    rescued_iv = txt[:16] # pega o iv2 da mensagem base64 decodificada
    print("iv rescued: ", rescued_iv)

def xor_ctxt():
    global key2
    print('---> enter the ctxt: \n', end='')
    ctxt = base64.b64decode(input().rstrip())
    rescued_iv = ctxt[:16] # pega o iv da mensagem base64 decodificada
    ctxt = ctxt[16:] # pega a mensagem base64 decodificada em si
    key2 = xor(to_blocks(ctxt))
    print("the key2: ", key2)

def menu():
    while True:
        print('MENU')
        options = [('Encrypt your secret', enc_plaintext),
                   ('Encrypt my secret', enc_flag),
                   ('Decrypt your secret', dec_plaintext),
                   ('Decrypt my secret', dec_flag),
                   ('Xor ciphered txt to get key2', xor_ctxt),
                   ('Exit', sys.exit)
                   ]
        for i, (op, _) in enumerate(options):
            print(f'{i+1} - {op}')
        print('Choice: ', end='')
        op = input().strip()
        #op = '1'
        assert op in ['1', '2', '3', '4', '5', '6', '7'], 'Invalid option'
        options[ord(op)-ord('1')][1]()


def main():
    print('Let\'s see if you are good enough in symmetric cryptography!\n')

    try:
        menu()
    except Exception as err:
        sys.exit(f'ERROR: {err}')


if __name__ == '__main__':
    main()
