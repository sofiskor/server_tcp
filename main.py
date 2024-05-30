import socket
import time
from datetime import datetime
import subprocess
import signal
import threading
import binascii
import struct
import Crypto.Cipher.AES as AES  #  pycryptodome
from textwrap import wrap
#variables______________________________________________________________________________________________________________
PORT = 1885  #  server port number
# IMEI = b'869139053762080'
# IMEI = b'352224455271973'
IMEI = b'352224455309021'
# IMEI = b'352224455341628'
TURN_MODEM_FIRMWARE_EMULATOR_ON = 1
BUFFER_SOCKET = 1024
TIMEOUT_SOCKET = 2
PERIOD = 2
COUNTER = 0
SOCKETMAXCONNECTIONS = 2
connected = False

last_msg_time = time.time()
counter = 0
config = {}
msgCounter = 0

global irq_1
global toSend
sendMessageCallCounter = 0
previousAddressToSend = -2
fileCS = 0
SIZE_OF_FIRMWARE_CHUNK = 768
# cs calc_______________________________________________________________________________________________________________
def calculateChecksum(firmware):
    fw_raw_to_get_cs = []  # split the firmware into 4 byte ints to calculate the cs
    for i in range(0, len(firmware), 4):
        fw_raw_to_get_cs.append(firmware[i:i + 4])
    # fw_raw_to_get_cs[0] = b'\x00\x00\x00\x00'  # test value
    # fw_raw_to_get_cs[1] = b'\x00\x00\x00\x01'  # test value
    # fw_raw_to_get_cs[2] = b'\x00\x00\x00\x01'  # test value
    # fw_raw_to_get_cs[3] = b'\x00\x00\x00\x01'  # test value
    # print(f'fw_raw_to_get_cs[0] = {int.from_bytes((fw_raw_to_get_cs[0]))}')  # test print
    # print(f'fw_raw_to_get_cs[1] = {int.from_bytes((fw_raw_to_get_cs[1]))}')  # test print
    # print(f'fw_raw_to_get_cs[0] = {int.from_bytes((fw_raw_to_get_cs[2]))}')  # test print
    # print(f'fw_raw_to_get_cs[1] = {int.from_bytes((fw_raw_to_get_cs[3]))}')  # test print
    fw_checksum = 0
    f = open('checksums.txt', 'w+')  # for the sake of knowing for sure we are sending the same we have in file
    for i in range(0, len(fw_raw_to_get_cs), 1):
        fw_checksum = (fw_checksum + int.from_bytes(fw_raw_to_get_cs[i], 'little')) % 4294967296
        # print(f'checksum calculated at step {i} = {fw_checksum}')
        hexval = hex(int.from_bytes(fw_raw_to_get_cs[i], 'little'))
        f.write(f'data for step {i} = {hexval}\n')  # read the file again
        f.write(f'checksum calculated at step {i} = {fw_checksum}\n')  # read the file again
        f.write(f'checksum calculated at step hex {i} = {hex(fw_checksum)}\n')  # read the file again
    print(f'fw_raw_to_get_cs (quantity of 4 byte blocks) = {len(fw_raw_to_get_cs)}')
    print(f'checksum for firmware in hex = {hex(4294967296 - fw_checksum)}')
    f.close()
    return 4294967296 - fw_checksum


# cs calc end___________________________________________________________________________________________________________
# encryption:___________________________________________________________________________________________________________
TEST_KEY = b'E6DbxKcQHrwrrXr2P9RAmVUCOf2YXUpB'  #  Dima's hardcoded cipher key for traffic

def encrypt(sendMessageSize):
    # keyAES = b'\x08\x06\x08\x02\x00\x07\x00\x05\x09\x07\x00\x09\x01\x04\x09\x00'  # №1
    # keyAES = b'\x08\x06\x08\x04\x05\x07\x00\x05\x01\x02\x05\x07\x04\x05\x02\x00'  # №3
    # keyAES = b'\x08\x06\x08\x04\x05\x07\x00\x05\x01\x01\x09\x04\x08\x03\x08\x00'  # №4
    # keyAES = b'\x08\x06\x08\x04\x05\x07\x00\x05\x01\x02\x05\x07\x07\x04\x02\x00'  # №5 868457051257742
    keyAES = b'E6DbxKcQHrwrrXr2'  # №Dima's key hardcoded in BS
    print(f'KeyAES = {keyAES}')
    iv = bytes((0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F))
    with open('firmware.bin', 'rb') as firmware:
        fwRaw = firmware.read()
    fwRaw = bytearray(fwRaw)
    print(f'Init vector = {iv}')
    print(f'Raw firmware length = {len(fwRaw)}')
    print(f'Padding... ')
    if len(fwRaw) % 16 != 0:  # firmware must be % 16 == 0  # padding
        fwRaw += b'\0' * (16 - len(fwRaw) % 16)

    fwRaw = fwRaw + b'\00\00\00\00\00\00\00\00\00\00\00\00'  # extra padding for checksum
    print(f'Raw firmware padded length = {len(fwRaw)}')
    print(f'Calculating the raw padded firmware checksum... ')
    csRaw = calculateChecksum(fwRaw)  # get cs raw
    print(f'firmware_raw length = {len(fwRaw)}')
    fwRaw = fwRaw + csRaw.to_bytes(4, 'little')
    # fwNotEncrypted = sum(fwRaw)
    cipher = AES.new(key=keyAES, mode=AES.MODE_CBC, iv=iv)
    fwEncrypted = cipher.encrypt(fwRaw)
    print(f'Calculating the encrypted padded firmware checksum... ')
    csEncrypted = calculateChecksum(fwEncrypted)  # get cs encrypted
    print(f'firmware_encrypted length = {len(fwEncrypted)}')
    with open('firmware.bin', 'wb') as firmware:
        fwRaw = firmware.write(fwEncrypted)
    print(f'firmware_encrypted chunk 0 = {fwEncrypted[0:sendMessageSize-1]}')
    print(f'firmware_encrypted chunk 1 = {fwEncrypted[sendMessageSize:(sendMessageSize*2 - 1)]}')
    decipher = AES.new(key=keyAES, mode=AES.MODE_CBC, iv=iv)  # key len 16 means aes-128
    decrypted = decipher.decrypt(fwEncrypted)
    print(f'firmware_decrypted chunk 0 = {decrypted[0:sendMessageSize - 1]}')
    print(f'firmware_decrypted chunk 1 = {decrypted[sendMessageSize:(sendMessageSize*2 - 1)]}')
    print('Waiting for a request from server')
    f = open('firmware.bin', 'rb')  # for the sake of knowing for sure we are sending the same we have in file
    fwEncryptedFile = f.read()  # read the file again
    f.close()
    fw = []
    for x in range(0, len(fwEncryptedFile), sendMessageSize):  # split it into 512 bytes chunks
        fw.append(fwEncryptedFile[x:x + sendMessageSize])
    ggg = 0
    for i in range(len(fw)):  # calculate checksums for every chunk
        ggg = ggg + sum(fw[i])
        print(f'Checksum for line {i} =  {ggg}')
    fwEncryptedFileLength = len(fwEncryptedFile)
    print(f'Again the checksum of the encrypted firmware = {hex(csEncrypted)}')
    print(f'Again the length of the encrypted firmware = {fwEncryptedFileLength}')
    return [fw, csEncrypted, fwEncryptedFileLength]
# encryption end:_______________________________________________________________________________________________________



def thread_function(name):
    global irq_1
    irq_1 = 0
    global toSend
    while 1:
        try:
            toSend = input('May enter new value\n')
            irq_1 = 1
            print('Entered = ' + toSend + ', irq_1 = ' + str(irq_1) + '\n')
        except:
            print('empty')


x = threading.Thread(target=thread_function, args=(1,))
x.start()
fw, csEncrypted, fwEncryptedFileLength = encrypt(SIZE_OF_FIRMWARE_CHUNK)

while True:
    global irq_1
    global toSend
    print('Trying to open new socket')
    sock = socket.socket()
    sock.bind(('', PORT))
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.listen(SOCKETMAXCONNECTIONS)
    con, address = sock.accept()
    con.settimeout(TIMEOUT_SOCKET)  # will close the socket after TIMEOUT_SOCKET seconds
    print('New connect from: ', address)
    while True:

        if irq_1 != 0:
            irq_1 = 0
            # con.send(b'''Heil Kim Jong Un''')
            # toSend = bytes()
            # con.send(bytes(toSend, 'utf-8'))
            # bytes = toSend.split(',')  # bytes are sent one by one with , between the in hex format
            # bytesUpdated = []
            # keys = str()
            # for i in bytes:
            #     bytesUpdated.append(int(i, 16))
            #     keys = keys + 'B'
            # print(bytesUpdated)
            # values = bytesUpdated
            # packer = struct.Struct(keys)
            # packed_data = packer.pack(*values)
            toSendSplit = [toSend[i:i+2] for i in range(0, len(toSend), 2)]  # bytes are entered one by one in hex format. 30313233 to send 1234 in ascii
            toSendSplitInt = []
            for i in toSendSplit:
                toSendSplitInt.append(int(i, 16))
            lineToSend = b''
            for i in toSendSplitInt:
                lineToSend = lineToSend + i.to_bytes(1, 'little')
            # lineToSend = toSendSplitInt[0].to_bytes(1, 'little')
            # val = hex(val)
            print(f'Entered = {lineToSend}, len = {len(lineToSend)}')
            # inputToSendBytes = toSend.to_bytes(4, 'little')
            # ToSend = int.from_bytes(toSend, "little")
            con.send(lineToSend)
            # con.send(bytes(toSend + str(lines), 'utf-8'))
            print("supposedly sent")
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # getTCPInfo(s)
        counter = counter + 1
        if counter % 60 == 0:
            print("Note: ", counter / 60, ' minutes passed')
        try:
            data = con.recv(BUFFER_SOCKET)  # blocking. waiting for some data
            if not data:
                print("Error, no data.")
                break
        except socket.timeout:
            # print("Error, timeout")
            data = None
        except ConnectionResetError:
            print("Note: " 'connection reset error')
            break
        except ConnectionAbortedError:
            print("Note: " 'connection aborted error')
            break

        if data is not None:
            print('\n')
            current_datetime = datetime.now()
            print(current_datetime)
            f = open('rxLog.txt', 'a')
            f.write(str(current_datetime) + '\n')
            f.write(str(data) + '\n')
            f.close()
            print('Received data:', data)
            print('Message length:', len(data))
            msgCounter = msgCounter + 1
            if TURN_MODEM_FIRMWARE_EMULATOR_ON == 1:
                if data[0] == 0x01:
                    if len(data) != 5:
                        print('PING error: Invalid packet payload length')
                    if data[1:5] != bytes((0x01, 0x00, 0x00, 0x00)):
                        print('PING error: incorrect PING message')
                    dat = b"\x81\x01\x00\x00\x00"  #  command_lenLSB_lenMSB_dummy_cs
                    print(f'dat = {str(dat)}')
                    con.send(dat)
                    f = open('rxLog.txt', 'a')
                    f.write(str(current_datetime) + '\n')
                    f.write(str(dat) + '\n')
                    f.close()
                elif data[0] == 0x02:
                    if len(data) != 44:
                        print('VERSION REQUEST error: Invalid packet length')
                    if data[1] != 0x28:  #  len of this message data
                        print('VERSION REQUEST: incorrect payload')
                    # fwCS = (4294967295 - sum(lines)) % 4294967295  # 4294967295 = 0xFFFFFFFF
                    # print(f'fileCS =  {fwCS},{type(fwCS)}')
                    # fwBytesCS = fwCS.to_bytes(4, 'little')
                    # print(f'fwCS =  {fwCS},{type(fwCS)}')
                    chunkLength = int.from_bytes(data[3:7], "little")
                    csEncryptedBytes = csEncrypted.to_bytes(4, 'little')
                    print("Sending the info")
                    fileLenBytes = fwEncryptedFileLength.to_bytes(4, 'little')
                    print(f'fileLenBytes =  {fileLenBytes},{type(fileLenBytes)}')  #  0x82 X_XX_XXXX_XXXX_XXXX_XXXX_X - code_length_timestamp_version_fwSize_fileChecksumm_cs.
                    dat = b"\x82\x10\x00\xA0\xE6\16\x62\x01\x00\x00\x00" + fileLenBytes + csEncryptedBytes
                    cs = (256 - int((sum(dat[3:]) % 256))) % 256
                    res2 = cs.to_bytes(1, 'big')
                    print(f'res2 = {res2},{type(res2)}')
                    dat = dat + res2
                    print(f'data to send = {dat}')
                    con.send(dat)
                    f = open('rxLog.txt', 'a')
                    f.write(str(current_datetime) + '\n')
                    f.write(str(dat) + '\n')
                    f.close()
                elif data[0] == 0x03:
                    addressToSend = int.from_bytes(data[3:7], "little")
                    requestedSize = int.from_bytes(data[7:11], "little")
                    print(f'Requested size =  {requestedSize},{type(requestedSize)}')
                    print(f'Requested address =  {addressToSend},{type(addressToSend)}')
                    sendMessageCallCounter = int(addressToSend / requestedSize)
                    # sendMessageCallCounter = sendMessageSize
                    print("Sending the data")
                    # dat = b"\x83\x00\x0E\x00\x00\x00\x0A\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                    mLength = len(fw[sendMessageCallCounter])
                    mLengthFull = len(fw[sendMessageCallCounter]) + 4
                    mLength = mLength.to_bytes(4, 'little')
                    mLengthFull = mLengthFull.to_bytes(2, 'little')
                    print(f'mLen1 = {str(mLength)}')
                    print(f'mLen2 = {str(mLengthFull)}')
                    dat = b"\x83" + mLengthFull + mLength + fw[sendMessageCallCounter]
                    print(dat)
                    res = int(256 - (sum(dat[3:]) % 256)) % 256
                    print(f'res = {res},{type(res)}')
                    # res = (128)
                    packer = struct.Struct('B')
                    res2 = packer.pack(res)
                    # res2 = res.encode(encoding='ASCII')
                    # res2 = bytes(res, 'utf-8')
                    dat = dat + res2
                    print(f'res = {res2},{type(res2)}')
                    print(dat)
                    if previousAddressToSend != addressToSend:
                        fileCS = fileCS + res
                        print(f'fileCS = {fileCS},{type(fileCS)}')
                    previousAddressToSend = addressToSend
                    con.send(dat)
                    f = open('rxLog.txt', 'a')
                    f.write(str(current_datetime) + '\n')
                    f.write(str(dat) + '\n')
                    f.close()
                else:
                    dat = b"\x89\x01\x00\x00\x00"
                    # dat = b"\x31\x32\x33\x34\x35"
                    # dat = b"\x30\x31\x32"
                    print(f'Data to send = {str(dat)}')
                    con.send(dat)
                    f = open('rxLog.txt', 'a')
                    f.write(str(current_datetime) + '\n')
                    f.write(str(dat) + '\n')
                    f.close()
                current_datetime = datetime.now()
                print(f'Data sent at time = {current_datetime}')

            if not connected and data == IMEI:
                connected = True
                print('Valid IMEI received')
                f = open('rxLog.txt', 'a')
                f.write("Reset happened" + '\n')
                f.close()
            elif connected:
                pass
        else:
            continue
        # con.send(b'''Ground Control to Major Tom. And there's nothing I can do''')
        # con.send(b'''Received your report, comrade''')
        # COUNTER
        print('msg № total = ', msgCounter)
        # if connected:
        #     if (time.time() - last_msg_time) > PERIOD:
        #         last_msg_time = time.time()
        #         pkt = nero.create_packet(0x01)
        #         # con.send(pkt)
        #         # print('Send data:', pkt)
        #     else:
        #         # sock.close()
        #         print('Connection closed')
        #         break

    # connected = False
