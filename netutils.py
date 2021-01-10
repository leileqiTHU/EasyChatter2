import socket
import time
import cv2
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome import Random
import rsa
class NetFunctions(object):
    def encrypt(self,data, pubkey):
        print(len(data))
        cipher = b''
        while len(data):
            cipher += rsa.encrypt(data[:240], pubkey)
            data = data[240:]
            print(len(cipher))
        return cipher
    def decrypt(self,cipher, privkey):
        data = b''
        while(len(cipher)):
            data+=rsa.decrypt(cipher[:256],privkey)
            cipher = cipher[256:]

        return data
    def sendData(self,serversocket, stringData,key=None):
        if key!=None:
            iv = Random.new().read(AES.block_size)
            mycipher = AES.new(key, AES.MODE_CFB, iv)
            cipherData = iv+mycipher.encrypt(stringData)
        else:
            cipherData = stringData
        # print("senddata ticket length:"+str(len(cipherData)))
        byte = str.encode(str(len(cipherData)).ljust(160)) 
        
        # print("senddata ticket length decoded from byte: "+byte.decode())
        data = byte+cipherData
        # print(str(len(data)))
        serversocket.sendall(data)
    def recvData(self,clientsocket,key=None,ip=None,type = 'udp'):
        if type=='udp':
            data,client = clientsocket.recvfrom(65535)
            if data==b'':
                return
            #只接收对应ip发来的数据
            if ip!=None:
                while client[0]!=ip:
                    data,client = clientsocket.recvfrom(65535)
            count = len(data)-160
            length = int(data[:160])
            data = data[160:]
            remain = length-count
            while remain:
                newBuf, client = clientsocket.recvfrom(remain)

                if(not newBuf):
                    return None
                data+=newBuf
                remain-=len(newBuf)
            if key==None:
                return data
            else:
                mydecrypt = AES.new(key, AES.MODE_CFB, data[:16])
                plainData = mydecrypt.decrypt(data[16:])
                return plainData
        else:
            data = clientsocket.recv(65535)
            print('s3')
            if data==b'':
                return
            count = len(data)-160
            length = int(data[:160])
            data = data[160:]
            remain = length-count
            while remain:
                newBuf = clientsocket.recv(remain)

                if(not newBuf):
                    return None
                data+=newBuf
                remain-=len(newBuf)
            print(len(data))
            if key==None:
                return data
            else:
                mydecrypt = AES.new(key, AES.MODE_CFB, data[:16])
                plainData = mydecrypt.decrypt(data[16:])
                return plainData