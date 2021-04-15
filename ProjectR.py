#Mizogg.co.uk 12/03/21 ProjectR (5Scanner)
#Install all Modules
#pip3 install bit chainside-btcpy eth_keys eth-hash[pycryptodome]
import random
from random import SystemRandom
import secrets
from bit import *
from bit.format import bytes_to_wif
from binascii import hexlify
import eth_keys
from eth_keys import keys
from btcpy.structs.crypto import PublicKey
from btcpy.structs.address import P2wpkhAddress
import multiprocessing
from multiprocessing import Pool
import atexit
from time import time
from datetime import timedelta, datetime


def seconds_to_str(elapsed=None):
    if elapsed is None:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    else:
        return str(timedelta(seconds=elapsed))


def log(txt, elapsed=None):
    colour_cyan = '\033[36m'
    colour_reset = '\033[0;0;39m'
    colour_red = '\033[31m'
    print('\n ' + colour_cyan + '  [TIMING]> [' + seconds_to_str() + '] ----> ' + txt + '\n' + colour_reset)
    if elapsed:
        print("\n " + colour_red + " [TIMING]> Elapsed time ==> " + elapsed + "\n" + colour_reset)


def end_log():
    end = time()
    elapsed = end-start
    log("End Program", seconds_to_str(elapsed))


start = time()
atexit.register(end_log)
log("Start Program")

print("Loading Address List Please Wait and Good Luck...")
with open("biglist.txt","r") as m: #Your Address List mix of addresses
    add = m.read().split()
add= set(add)

#Examples
#This has been made for Bitcoin Puzzle Transaction https://privatekeys.pw/puzzles/bitcoin-puzzle-tx
#Puzzle 1-10 ran = secrets.SystemRandom().randrange(1,1023)     #TestScan # Already found 
#Puzzle 1-20 ran = secrets.SystemRandom().randrange(1,1048575)     #TestScan # Already found 
#Puzzle 1-30 ran = secrets.SystemRandom().randrange(1,1073741823)     #TestScan # Already found 
#Puzzle 1-63 ran = secrets.SystemRandom().randrange(1,9223372036854775807)      # Already found
#Puzzle 64 ran = secrets.SystemRandom().randrange(9223372036854775807,18446744073709551615)
#Puzzle 1-160 ran = secrets.SystemRandom().randrange(1,1461501637330902918203684832716283019655932542975)
#Puzzle 64-160 ran = secrets.SystemRandom().randrange(9223372036854775807,1461501637330902918203684832716283019655932542975)
#Puzzle 60 ran = secrets.SystemRandom().randrange(576460752303423488,1152921504606846975)      # Already found
#Puzzle 70 ran = secrets.SystemRandom().randrange(590295810358705651712,1180591620717411303423)      # Already found
#Puzzle 80 ran = secrets.SystemRandom().randrange(1208925819614629174706176,2417851639229258349412351)
#Puzzle 90 ran = secrets.SystemRandom().randrange(618970019642690137449562112,1237940039285380274899124223)
#Puzzle 100 ran = secrets.SystemRandom().randrange(633825300114114700748351602688,1267650600228229401496703205375)
#Puzzle 110 ran = secrets.SystemRandom().randrange(649037107316853453566312041152512,1298074214633706907132624082305023)
#Puzzle 120 ran = secrets.SystemRandom().randrange(664613997892457936451903530140172288,1329227995784915872903807060280344575)
#Puzzle 130 ran = secrets.SystemRandom().randrange(680564733841876926926749214863536422912,1361129467683753853853498429727072845823)
#Puzzle 140 ran = secrets.SystemRandom().randrange(696898287454081973172991196020261297061888,1393796574908163946345982392040522594123775)
#Puzzle 150 ran = secrets.SystemRandom().randrange(713623846352979940529142984724747568191373312,1427247692705959881058285969449495136382746623)
#Puzzle 160 ran = secrets.SystemRandom().randrange(730750818665451459101842416358141509827966271488,1461501637330902918203684832716283019655932542975)
#Full Range Scan #ran = secrets.SystemRandom().randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494275)
#ran = random.getrandbits(254)
#ran = random.SystemRandom().getrandbits(254)
#ran = secrets.randbits(250)
#ran = random.randrange(2**64)
#ran = rand.getrandbits(256) 
#ran = rand.getrandbits(256)
#ran = secretsGenerator.randrange(8993229949524465672,8993229949524482056)
#ran = secretsGenerator.getrandbits(256)
#ran = Crypto.Random.random.getrandbits(256)
#ran = random.SystemRandom().getrandbits(256)
#ran = secrets.SystemRandom().getrandbits(196)
#ran = secrets.SystemRandom().randrange(2**196)
#ran = SystemRandom().randrange(2**254)
#ran = secrets.randbits(254)
#ran = secrets.randbelow(115792089237316195423570985008687907852837564279074904382605163141518161494337)
  
r = 0
cores=1 #CPU Control Set Cores

def seek(r):
        while True:
            ran = secrets.SystemRandom().randrange(1,115792089237316195423570985008687907852837564279074904382605163141518161494337)  #Puzzle 1-20 #Use Examples 
            key1 = Key.from_int(ran)
            wif = bytes_to_wif(key1.to_bytes(), compressed=False) #Uncompressed WIF
            wif2 = bytes_to_wif(key1.to_bytes(), compressed=True) #compressed WIF
            key2 = Key(wif)
            caddr = key1.address											#Legacy compressed address
            uaddr = key2.address											#Legacy uncompressed address
            saddr = key1.segwit_address										#Segwit address
            pub1 = hexlify(key1.public_key).decode()
            pub2 = hexlify(key2.public_key).decode()
            pubk1 = PublicKey.unhexlify(pub1)
            pubk2 = PublicKey.unhexlify(pub2)
            bcaddr = P2wpkhAddress(pubk1.hash(), version=0, mainnet=True)	#Segwit (bech32) compressed address
            buaddr = P2wpkhAddress(pubk2.hash(), version=0, mainnet=True)	#Segwit (bech32) uncompressed address
            myhex = "%064x" % ran
            private_key = myhex[:64]
            private_key_bytes = bytes.fromhex(private_key)
            public_key_hex = keys.PrivateKey(private_key_bytes).public_key
            public_key_bytes = bytes.fromhex(str(public_key_hex)[2:])
            eaddr = keys.PublicKey(public_key_bytes).to_address()			#Eth address
            if caddr in add:
                print ("Nice One Found!!!",ran, caddr, wif2, private_key) #Legacy compressed address
                s1 = str(ran)
                s2 = caddr
                s3 = wif2
                s4 = private_key
                f=open(u"CompressedWinner.txt","a") #Output File of Legacy compressed Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4)
                f.write("\n")
                f.close()
                continue #break or continue
            if uaddr in add:
                print ("Nice One Found!!!",ran, uaddr, wif, private_key) #Legacy uncompressed address
                s1 = str(ran)
                s2 = uaddr
                s3 = wif
                s4 = private_key
                f=open(u"UncompressedWinner.txt","a") #Output File of Legacy uncompressed Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4)
                f.write("\n")
                f.close()
                continue #break or continue
            if saddr in add:
                print ("Nice One Found!!!",ran, saddr, wif, private_key) #Segwit address
                s1 = str(ran)
                s2 = saddr
                s3 = wif
                s4 = private_key
                f=open(u"Winner3.txt","a") #Output File of Segwit Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4)
                f.write("\n")                
                f.close()
                continue #break or continue
            if str(bcaddr) in add:
                print ("Nice One Found!!!",ran, str(bcaddr)) #Segwit (bech32) compressed address
                s1 = str(ran)
                s2 = str(bcaddr)
                s3 = wif
                s4 = private_key
                f=open(u"bech32CompressedWinner.txt","a") #Output File of Segwit (bech32) compressed Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4) 
                f.write("\n")                
                f.close()
                continue #break or continue
            if str(buaddr) in add:
                print ("Nice One Found!!!",ran, str(buaddr)) #Segwit (bech32) uncompressed address
                s1 = str(ran)
                s2 = str(buaddr)
                s3 = wif
                s4 = private_key
                f=open(u"bechUncompressedWinner.txt","a") #Output File of Segwit (bech32) uncompressed Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4) 
                f.write("\n")
                f.close()
                continue #break or continue
            if eaddr in add:
                print ("Nice One Found!!!",ran, private_key, eaddr) #Eth address
                s1 = str(ran)
                s2 = eaddr
                s3 = wif
                s4 = private_key
                f=open(u"EthWinner.txt","a") #Output File of Eth Wallet Found
                f.write(s1+":"+s2+":"+s3+":"+s4) 
                f.write("\n")
                f.close()
                continue #break or continue
            else:
                colour_cyan = '\033[36m'
                colour_reset = '\033[0;0;39m'
                colour_red = '\033[31m'
                print ("\n " + colour_cyan + "ProjectR---" + colour_red + "---Good--Luck--Happy--Hunting--Mizogg.co.uk&Chad---" + colour_cyan + "---ProjectR"  + colour_reset) # Running Display Output
                print (myhex)
                print (caddr)
                print (uaddr)
                print (saddr)
                print (bcaddr)
                print (buaddr)
                print (eaddr)
                print ("\n ")
                print(colour_cyan + seconds_to_str())
#CPU Control Command
if __name__ == '__main__':
        jobs = []
        for r in range(cores):
                p = multiprocessing.Process(target=seek, args=(r,))
                jobs.append(p)
                p.start()