import pymysql
import socket
import time
import numpy as np
from Cryptodome.Cipher import AES
from Cryptodome import Random
import rsa
import pymysql
def sendData(serversocket, stringData,key=None,delay=None):
    print('ssssssssssssssssss')
    if key!=None:
        iv = Random.new().read(AES.block_size)
        mycipher = AES.new(key, AES.MODE_CFB, iv)
        cipherData = iv+mycipher.encrypt(stringData)
    else:
        cipherData = stringData
    print("senddata ticket length:"+str(len(cipherData)))
    byte = str.encode(str(len(cipherData)).ljust(160)) 
    
    print("senddata ticket length decoded from byte: "+byte.decode())
    data = byte+cipherData
    print(str(len(data)))
    serversocket.sendall(data)
    if delay!=None:
        time.sleep(delay)#为了解决黏包现象
def recvData(clientsocket,key=None):
    data = clientsocket.recv(65535)
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

def judgeuser(iduser, password):
    conn = pymysql.connect('localhost',user='root',passwd='leileqi99',db='crypt_exp')
    cursor = conn.cursor()
    sql = "select * from crypt_exp.user_table where idusers='"+iduser+"' and password = '"+str(password)+"'"
    print(sql)
    res = cursor.execute(sql) 
    cursor.close()
    conn.close() 
    return res
def regist(iduser, password, pubkey):
    conn = pymysql.connect('localhost',user='root',passwd='leileqi99',db='crypt_exp')
    cursor = conn.cursor()
    sql = "select * from crypt_exp.user_table where idusers='"+iduser+"'"
    print('x1')
    print('x2')
    res = cursor.execute(sql) 
    if res!=0:
        return False 
        cursor.close()
        conn.close()
    print('x3')
    sql = "insert into crypt_exp.user_table (idusers, password,publickey) values ('"+str(iduser)+"','"+str(password)+"','"+pubkey+"')"
    print(sql)
    res = cursor.execute(sql)
    print('x4') 
    cursor.execute('commit') 
    cursor.close()
    conn.close() 
    if res==0:
        return False
    return True
def updateIp(iduser, ip):
    conn = pymysql.connect('localhost',user='root',passwd='leileqi99',db='crypt_exp')
    cursor = conn.cursor()
    sql = "update crypt_exp.user_table set ip='"+ip+"' where idusers = '"+str(iduser)+"'"
    print(sql)
    res = cursor.execute(sql) 
    cursor.execute('commit') 
    cursor.close()
    conn.close() 
    return res
def exportPubKey(iduser):
    conn = pymysql.connect('localhost',user='root',passwd='leileqi99',db='crypt_exp')
    cursor = conn.cursor()
    sql = "select * from crypt_exp.user_table where idusers='"+iduser+"'"
    res = cursor.execute(sql)
    print(res)
    if res==0:
        return None
    else:
        data = cursor.fetchone() 
        cursor.close()
        conn.close() 
        return (data[2],rsa.PublicKey.load_pkcs1(data[-1]))
def encrypt(data, pubkey):
    print(len(data))
    cipher = b''
    while len(data):
        cipher += rsa.encrypt(data[:240], pubkey)
        data = data[240:]
        print(len(cipher))
    return cipher
def decrypt(cipher, privkey):
    data = b''
    while(len(cipher)):
        data+=rsa.decrypt(cipher[:256],privkey)
        cipher = cipher[256:]
    return data
# querydb(cursor, idusers, '12345')
listensocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listenhost = socket.gethostname()
listensocket.bind(('0.0.0.0', 8080))
while True:
    try:
        listensocket.listen(5)
        clienttcp, clienttcpaddr = listensocket.accept()
        clienttcp.settimeout(1)
        # (pubkey, privkey) = rsa.newkeys(512)
        with open('KDCpubkey.pem') as f:
            pubkey = rsa.PublicKey.load_pkcs1(f.read())
        with open('KDCprivkey.pem') as f:
            privkey = rsa.PrivateKey.load_pkcs1(f.read())  
        
        #发送KDCpubkey
        print("t1")
        sendData(clienttcp, str((pubkey.n, pubkey.e)).encode(),key=None)
        print("t2")
        data = recvData(clienttcp)
        print("t3")
        data = decrypt(data, privkey)
        (iduser,password, verify_code,pubkey) = eval(data.decode())
        if pubkey!=None:
            print('s1')
            res = regist(iduser, password, pubkey)
            print('s2')
            sendData(clienttcp, str(res).encode())
            continue

        print(iduser)
        print(password)

        if(judgeuser(iduser,password)):
            print("用户验证通过")
            updateIp(iduser, clienttcpaddr[0])
            Apubkey = exportPubKey(iduser)[-1]
            print("发送确认消息")
            signature = rsa.sign(verify_code, privkey, 'SHA-1')
            sendData(clienttcp,signature)
            print(clienttcpaddr[0])

            while True:
                print("接收目标")
                try:
                    data = recvData(clienttcp)
                except Exception as e:
                    print(e)
                    break
                iduser = data.decode()
                print("提取目标的公钥")
                res = exportPubKey(iduser)
                # print('s3')
                if res==None:
                    # print('s4') 
                    print("查无此人")
                    sendData(clienttcp,'no'.encode())
                    # print('s5')

                    continue
                # print('s2')
                sendData(clienttcp,'yes'.encode())
                # print('s1')
                (Bip,Bpubkey) = res
                #生成票据
                print("发送票据A")
                print('x1')
                data = str((Apubkey.save_pkcs1(),iduser)).encode()
                print('x2')
                ticket = encrypt(data, Bpubkey)
                print('x3')
                print('ticket length: '+str(len(ticket)))
                sendData(clienttcp,ticket,delay=0.5)
                print("发送IP地址")
                sendData(clienttcp, Bip.encode(),delay=0.5)
                print("发送B的公钥")
                sendData(clienttcp, Bpubkey.save_pkcs1(),delay=0.5)
            print("结束服务")
            clienttcp.close()
        else:
            sendData(clienttcp,'no'.encode())
            print("用户不存在，关闭连接")
            clienttcp.close()
    except Exception as e:
        print(e)
exit(0)
