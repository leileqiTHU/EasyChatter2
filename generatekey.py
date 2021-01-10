import rsa
(pubkey, privkey) = rsa.newkeys(2048)
with open('pubkey.pem','wb') as f:
    f.write(pubkey.save_pkcs1())
with open('privkey.pem','wb') as f:
    f.write(privkey.save_pkcs1())
(pubkey, privkey) = rsa.newkeys(2048)
with open('KDCpubkey.pem','wb') as f:
    f.write(pubkey.save_pkcs1())
with open('KDCprivkey.pem','wb') as f:
    f.write(privkey.save_pkcs1())