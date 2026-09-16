import serial
import time
import requests

from binascii import hexlify, unhexlify

from CryptoMobile.Milenage import Milenage

try:
    from smartcard.System import readers
    from smartcard.util import toHexString, toBytes
except ImportError:
    readers = None
    toHexString = None
    toBytes = None

try:
    from card.USIM import USIM
except ImportError:
    USIM = None

requests.packages.urllib3.disable_warnings()


# Abstraction functions

def milenage_res_ck_ik(ki, op, opc, rand):
    rand = unhexlify(rand)
    ki = unhexlify(ki)
    if op == None: 
        opc = unhexlify(opc)
        op = 16*b'\x00' # Dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        op = unhexlify(op)
        m = Milenage(op)
    res, ck, ik, ak = m.f2345(ki, rand)
    return hexlify(res), hexlify(ck), hexlify(ik)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def return_auts(rand, autn,ki,op,opc,sqn, amf=None):
    rand = unhexlify(rand)
    ki = unhexlify(ki)
    autn = unhexlify(autn)
    sqn = unhexlify(sqn)
    if amf is None:
        amf = b'\x00\x00'
    elif isinstance(amf, str):
        amf = unhexlify(amf)
    if op == None: 
        opc = unhexlify(opc)
        op = 16*b'\x00' # Dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        op = unhexlify(op)
        m = Milenage(op)
    macs = m.f1star(ki,rand,sqn,amf)
    ak = m.f5star(ki,rand)
    ak_xor_sqn = byte_xor(ak, sqn)
    return  ak_xor_sqn + macs


def return_imsi(serial_interface_or_reader_index):
    try:
        return read_imsi_2(serial_interface_or_reader_index)
    except:
        try:
            return get_imsi(serial_interface_or_reader_index)
        except:
            try:
                return https_imsi(serial_interface_or_reader_index)
            except:
                print('Unable to get IMSI. Pass --imsi, or use a modem / smartcard reader / HTTPS server.')
                exit(1)
        
def return_res_ck_ik(serial_interface_or_reader_index, rand, autn, ki, op, opc):
    if ki is not None and (op is not None or opc is not None):
        try:
            return milenage_res_ck_ik(ki, op, opc, rand)
        except:
            print('Unable to calculate Milenage RES/CK/IK. Check --ki and --op or --opc.')
            exit(1)
    else:
        try:
            return read_res_ck_ik_2(serial_interface_or_reader_index, rand, autn)
        except:
            try:        
                return get_res_ck_ik(serial_interface_or_reader_index, rand, autn)
            except:
                try:
                    return https_res_ck_ik(serial_interface_or_reader_index, rand, autn)
                except:
                    print('Unable to get RES/CK/IK. Pass --ki with --op or --opc, or use a modem / smartcard reader / HTTPS server.')
                    exit(1)




def get_imsi(serial_interface):

    imsi = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
    CLI.append('AT+CIMI\r\n')
    
    a = time.time()
    for i in range(len(CLI)):
        ser.write(CLI[i].encode())
        buffer = ''

        while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
            buffer +=  ser.read().decode("utf-8")
            
            if time.time()-a > 0.5:
                ser.write(CLI[i].encode())
                a = time.time() +1
            
        if i==0:    
            for m in buffer.split('\r\n'):
                if len(m) == 15:
                    imsi = m
         
    ser.close()
    return imsi


def get_res_ck_ik(serial_interface, rand, autn):
    res = None
    ck = None
    ik = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
   
    #CLI.append('AT+CRSM=178,12032,1,4,0\r\n')
    CLI.append('AT+CSIM=14,"00A40000023F00"\r\n')
    CLI.append('AT+CSIM=14,"00A40000022F00"\r\n')
    CLI.append('AT+CSIM=42,"00A4040010A0000000871002FFFFFFFF8903050001"\r\n')
    CLI.append('AT+CSIM=78,\"008800812210' + rand.upper() + '10' + autn.upper() + '\"\r\n')

    a = time.time()
    for i in CLI:
        ser.write(i.encode())
        buffer = ''
    
        while "OK" not in buffer and "ERROR" not in buffer:
            buffer +=  ser.read().decode("utf-8")
        
            if time.time()-a > 0.5:
                ser.write(i.encode())

                a = time.time() + 1
                
    for i in buffer.split('"'):
        if len(i)==4:
            if i[0:2] == '61':
                len_result = i[-2:]
    
    LAST_CLI = 'AT+CSIM=10,"00C00000' + len_result + '\"\r\n'
    ser.write(LAST_CLI.encode())
    buffer = ''
    
    while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
        buffer +=  ser.read().decode("utf-8")
        
    for result in buffer.split('"'):
        if len(result) > 10:
        

            res = result[4:20]
            ck = result[22:54]
            ik = result[56:88]
    
    ser.close()    
    return res, ck, ik
    

def _require_usim_backend():
    if readers is None or toHexString is None or toBytes is None or USIM is None:
        raise ImportError(
            "Smartcard support is not installed. Re-run ./install_deps.sh --with-usim"
        )


# Reader functions
def bcd(chars):
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]
    return bcd_string

def read_imsi(reader_index):
    _require_usim_backend()
    imsi = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))     
    data, sw1, sw2 = connection.transmit(toBytes('00A40000027F20'))
    data, sw1, sw2 = connection.transmit(toBytes('00A40000026F07'))
    data, sw1, sw2 = connection.transmit(toBytes('00B0000009'))  
    result = toHexString(data).replace(" ","")
    imsi = bcd(result)[-15:]
    
    return imsi

def read_res_ck_ik(reader_index, rand, autn):
    _require_usim_backend()
    res = None
    ck = None
    ik = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))    
    data, sw1, sw2 = connection.transmit(toBytes('00A40000022F00')) 
    data, sw1, sw2 = connection.transmit(toBytes('00A4040010A0000000871002FFFFFFFF8903050001'))   
    data, sw1, sw2 = connection.transmit(toBytes('008800812210' + rand.upper() + '10' + autn.upper()))   
    if sw1 == 97:
        data, sw1, sw2 = connection.transmit(toBytes('00C00000') + [sw2])         
        result = toHexString(data).replace(" ", "")
        res = result[4:20]
        ck = result[22:54]
        ik = result[56:88]          

    return res, ck, ik

# Reader functions - more generic using card module
def read_imsi_2(reader_index): #prepared for AUTS
    _require_usim_backend()
    a = USIM(int(reader_index))
    print(a.get_imsi())
    return a.get_imsi()
    
def read_res_ck_ik_2(reader_index,rand,autn):
    _require_usim_backend()
    a = USIM(int(reader_index))
    x = a.authenticate(RAND=toBytes(rand), AUTN=toBytes(autn))
    if len(x) == 1: # AUTS goes in RES field
        return toHexString(x[0]).replace(" ", ""), None, None
    elif len(x) > 2:
        return toHexString(x[0]).replace(" ", ""),toHexString(x[1]).replace(" ", ""),toHexString(x[2]).replace(" ", "") 
    else:
        return None, None, None


# HTTPS functions
def https_imsi(server):
    r = requests.get('https://' + server + '/?type=imsi', verify=False)
    return r.json()['imsi']

def https_res_ck_ik(server, rand, autn):
    r = requests.get('https://' + server + '/?type=rand-autn&rand=' + rand + '&autn=' + autn, verify=False)
    return r.json()['res'], r.json()['ck'], r.json()['ik']
