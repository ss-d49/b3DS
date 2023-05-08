#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util import Counter
from sys import argv
import struct
from argparse import ArgumentParser
import sys


def rol(val, r_bits, max_bits): return \
    (val << r_bits % max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


# Setup Keys and IVs
plain_counter = (int.from_bytes(b'\x01\x00\x00\x00\x00\x00\x00\x00', "big"),)
exefs_counter = (int.from_bytes(b'\x02\x00\x00\x00\x00\x00\x00\x00', "big"),)
romfs_counter = (int.from_bytes(b'\x03\x00\x00\x00\x00\x00\x00\x00', "big"),)
# 3DS AES Hardware Constant
Constant = struct.unpack(
    '>QQ', b'\x1F\xF9\xE9\xAA\xC5\xFE\x04\x08\x02\x45\x91\xDC\x5D\x52\x76\x8A')
# Retail keys
# KeyX 0x18 (New 3DS 9.3)
KeyX0x18 = struct.unpack(
    '>QQ', b'\x82\xE9\xC9\xBE\xBF\xB8\xBD\xB8\x75\xEC\xC0\xA0\x7D\x47\x43\x74')
# KeyX 0x1B (New 3DS 9.6)
KeyX0x1B = struct.unpack(
    '>QQ', b'\x45\xAD\x04\x95\x39\x92\xC7\xC8\x93\x72\x4A\x9A\x7B\xCE\x61\x82')
KeyX0x25 = struct.unpack(
    '>QQ', b'\xCE\xE7\xD8\xAB\x30\xC0\x0D\xAE\x85\x0E\xF5\xE3\x82\xAC\x5A\xF3')  # KeyX 0x25 (> 7.x)
KeyX0x2C = struct.unpack(
    '>QQ', b'\xB9\x8E\x95\xCE\xCA\x3E\x4D\x17\x1F\x76\xA9\x4D\xE9\x34\xC0\x53')  # KeyX 0x2C (< 6.x)

# Dev Keys: (Uncomment these lines if your 3ds rom is encrypted with Dev Keys)
# KeyX0x18 = struct.unpack('>QQ', '\x30\x4B\xF1\x46\x83\x72\xEE\x64\x11\x5E\xBD\x40\x93\xD8\x42\x76') # Dev KeyX 0x18 (New 3DS 9.3)
# KeyX0x1B = struct.unpack('>QQ', '\x6C\x8B\x29\x44\xA0\x72\x60\x35\xF9\x41\xDF\xC0\x18\x52\x4F\xB6') # Dev KeyX 0x1B (New 3DS 9.6)
# KeyX0x25 = struct.unpack('>QQ', '\x81\x90\x7A\x4B\x6F\x1B\x47\x32\x3A\x67\x79\x74\xCE\x4A\xD7\x1B') # Dev KeyX 0x25 (> 7.x)
# KeyX0x2C = struct.unpack('>QQ', '\x51\x02\x07\x51\x55\x07\xCB\xB1\x8E\x24\x3D\xCB\x85\xE2\x3A\x1D') # Dev KeyX 0x2C (< 6.x)


def process_exefs(cmd, f, g, part_off, exefs_off, sectorsize, exefsIV, NormalKey2C, p):
    f.seek(
        (part_off[0] + exefs_off[0]) * sectorsize)
    g.seek(
        (part_off[0] + exefs_off[0]) * sectorsize)
    exefsctr2C = Counter.new(
        128, initial_value=(exefsIV))
    exefsctrmode2C = AES.new(
        NormalKey2C.to_bytes(16, 'big'), AES.MODE_CTR, counter=exefsctr2C)
    if cmd == "encrypt":
        g.write(exefsctrmode2C.encrypt(
            f.read(sectorsize)))
    elif cmd == "decrypt":
        g.write(exefsctrmode2C.decrypt(
            f.read(sectorsize)))
    print(f"Partition {p:01} ExeFS: {cmd}ing: ExeFS Filename Table")

def setKeys(flags, p, KeyY, Const):
    if (flags[3] == 0x00):  # Uses Original Key
        KeyX = (KeyX0x2C[0]<<64) + KeyX0x2C[1]
        if (p == 0):
            print("Encryption Method: Key 0x2C")
    elif (flags[3] == 0x01):  # Uses 7.x Key
        KeyX = (KeyX0x25[0]<<64) + KeyX0x25[1]
        if (p == 0):
            print("Encryption Method: Key 0x25")
    elif (flags[3] == 0x0A):  # Uses New3DS 9.3 Key
        KeyX = (KeyX0x18[0]<<64) + KeyX0x18[1]
        if (p == 0):
            print("Encryption Method: Key 0x18")
    elif (flags[3] == 0x0B):  # Uses New3DS 9.6 Key
        KeyX = (KeyX0x1B[0]<<64) + KeyX0x1B[1]
        if (p == 0):
            print("Encryption Method: Key 0x1B")
    NormalKey = rol(
        (rol(KeyX, 2, 128) ^ KeyY) + Const, 87, 128)
    return NormalKey

def process(file, outfile, cmd):
    with open(file, 'rb') as f:
        with open(outfile, 'rb+') as g:
            print(file)  # Print the filename of the file being decrypted
            f.seek(0x100)  # Seek to start of NCSD header
            magic = f.read(0x04)
            if magic == b"NCSD":
                f.seek(0x188)
                ncsd_flags = struct.unpack('<BBBBBBBB', f.read(0x8))
                sectorsize = 0x200 * (2**ncsd_flags[6])

                for p in range(8):
                    # Seek to start of partition information, read offsets and lengths
                    f.seek((0x120) + (p*0x08))
                    part_off = struct.unpack('<L', f.read(0x04))


                    # Get the partition flags to determine encryption type.
                    f.seek(((part_off[0]) * sectorsize) + 0x188)
                    partition_flags = struct.unpack('<BBBBBBBB', f.read(0x8))
                    if cmd == "encrypt":
                        f.seek(0x1188)  # Get the backup partition flags
                        backup_flags = struct.unpack('<BBBBBBBB', f.read(0x8))

                    if (part_off[0] * sectorsize) > 0:  # check if partition exists
                        # check if the 'NoCrypto' bit (bit 3) is set
                        decrypted = (partition_flags[7] & 0x04)

                        if cmd == "decrypt" and decrypted:
                            sys.exit("Partition %1d: Already Decrypted?..." % (p))
                        elif cmd == "encrypt" and not decrypted:
                            sys.exit("Partition %1d: Already Encrypted?..." % (p))

                        # Find partition start (+ 0x100 to skip NCCH header)
                        f.seek(((part_off[0]) * sectorsize) + 0x100)
                        magic = f.read(0x04)

                        if magic == b"NCCH":  # check if partition is valid
                            f.seek(((part_off[0]) * sectorsize) + 0x0)
                            # KeyY is the first 16 bytes of partition RSA-2048 SHA-256 signature
                            part_keyy = struct.unpack('>QQ', f.read(0x10))

                            f.seek(((part_off[0]) * sectorsize) + 0x108)
                            # TitleID is used as IV joined with the content type.
                            tid = (int.from_bytes(f.read(0x8), "little"),)
                            # Get the IV for plain sector (TitleID + Plain Counter)
                            plain_iv = (tid + plain_counter)
                            # Get the IV for ExeFS (TitleID + ExeFS Counter)
                            exefs_iv = (tid + exefs_counter)
                            # Get the IV for RomFS (TitleID + RomFS Counter)
                            romfs_iv = (tid + romfs_counter)

                            # get exheader hash
                            f.seek((part_off[0] * sectorsize) + 0x160)
                            exhdr_sbhash = bytearray(f.read(0x20)).hex()

                            f.seek((part_off[0] * sectorsize) + 0x180)
                            # get extended header length
                            exhdr_len = (int.from_bytes(f.read(0x04), "little"),)

                            f.seek((part_off[0] * sectorsize) + 0x190)
                            # get plain sector offset
                            plain_off = (int.from_bytes(f.read(0x04), "little"),)
                            # get plain sector length
                            plain_len = (int.from_bytes(f.read(0x04), "little"),)

                            f.seek((part_off[0] * sectorsize) + 0x198)
                            logo_off = (int.from_bytes(f.read(0x04), "little"),)  # get logo offset
                            logo_len = (int.from_bytes(f.read(0x04), "little"),)  # get logo length

                            f.seek((part_off[0] * sectorsize) + 0x1A0)
                            exefs_off = (int.from_bytes(f.read(0x04), "little"),)  # get exefs offset
                            exefs_len = (int.from_bytes(f.read(0x04), "little"),)  # get exefs length

                            f.seek((part_off[0] * sectorsize) + 0x1B0)
                            romfs_off = (int.from_bytes(f.read(0x04), "little"),)  # get romfs offset
                            romfs_len = (int.from_bytes(f.read(0x04), "little"),)  # get romfs length

                            # get exefs hash
                            f.seek((part_off[0] * sectorsize) + 0x1C0)
                            exefs_sbhash = bytearray(f.read(0x20)).hex()

                            # get romfs hash
                            f.seek((part_off[0] * sectorsize) + 0x1E0)
                            romfs_sbhash = bytearray(f.read(0x20)).hex()

                            plainIV = (plain_iv[0]<<64) + plain_iv[1]
                            exefsIV = KeyX = (exefs_iv[0]<<64) + exefs_iv[1]
                            romfsIV = KeyX = (romfs_iv[0]<<64) + romfs_iv[1]
                            KeyY = KeyX = (part_keyy[0]<<64) + part_keyy[1]
                            Const = KeyX = (Constant[0]<<64) + Constant[1]

                            KeyX2C = KeyX = (KeyX0x2C[0]<<64) + KeyX0x2C[1]
                            NormalKey2C = rol(
                                (rol(KeyX2C, 2, 128) ^ KeyY) + Const, 87, 128)

                            # fixed crypto key (aka 0-key)
                            if (partition_flags[7] & 0x01):
                                NormalKey = 0x00
                                NormalKey2C = 0x00
                            else:
                                if cmd == "encrypt":
                                    NormalKey = setKeys(backup_flags, p, KeyY, Const)
                                elif cmd == "decrypt":
                                    NormalKey = setKeys(partition_flags, p, KeyY, Const)



                            if (exhdr_len[0] > 0):
                                # enrypt exheader
                                f.seek((part_off[0] + 1) * sectorsize)
                                g.seek((part_off[0] + 1) * sectorsize)
                                exhdr_filelen = 0x800
                                exefsctr2C = Counter.new(
                                    128, initial_value=(plainIV))
                                exefsctrmode2C = AES.new(
                                    NormalKey2C.to_bytes(16, 'big'), AES.MODE_CTR, counter=exefsctr2C)
                                print(f"Partition {p:01} ExeFS: {cmd}ing: ExHeader")
                                if cmd == "encrypt":
                                    g.write(exefsctrmode2C.encrypt(
                                        f.read(exhdr_filelen)))
                                elif cmd == "decrypt":
                                    g.write(exefsctrmode2C.decrypt(
                                        f.read(exhdr_filelen)))

                            if (exefs_len[0] > 0):
                                if cmd == "decrypt":
                                    # decrypt exefs filename table
                                    process_exefs(cmd, f, g, part_off, exefs_off, sectorsize, exefsIV, NormalKey2C, p)


                                if (cmd == "decrypt" and (partition_flags[3] == 0x01 or partition_flags[3] == 0x0A or partition_flags[3] == 0x0B)) or \
                                (cmd == "encrypt" and (backup_flags[3] == 0x01 or backup_flags[3] == 0x0A or backup_flags[3] == 0x0B)):
                                    code_filelen = 0
                                    for j in range(10):  # 10 exefs filename slots
                                        # get filename, offset and length
                                        f.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize) + j*0x10)
                                        g.seek(
                                            ((part_off[0] + exefs_off[0]) * sectorsize) + j*0x10)
                                        exefs_filename = struct.unpack(
                                            '<8s', g.read(0x08))
                                        if exefs_filename[0] == b".code\x00\x00\x00":
                                            code_fileoff = struct.unpack(
                                                '<L', g.read(0x04))
                                            code_filelen = struct.unpack(
                                                '<L', g.read(0x04))
                                            datalenM = int(
                                                (code_filelen[0]) / (1024*1024))
                                            datalenB = int(
                                                (code_filelen[0]) % (1024*1024))
                                            ctroffset = int(
                                                (code_fileoff[0] + sectorsize) / 0x10)
                                            exefsctr = Counter.new(
                                                128, initial_value=(exefsIV + ctroffset))
                                            exefsctr2C = Counter.new(
                                                128, initial_value=(exefsIV + ctroffset))
                                            exefsctrmode = AES.new(
                                                NormalKey.to_bytes(16, 'big'), AES.MODE_CTR, counter=exefsctr)
                                            exefsctrmode2C = AES.new(
                                                NormalKey2C.to_bytes(16, 'big'), AES.MODE_CTR, counter=exefsctr2C)
                                            f.seek(
                                                (((part_off[0] + exefs_off[0]) + 1) * sectorsize) + code_fileoff[0])
                                            g.seek(
                                                (((part_off[0] + exefs_off[0]) + 1) * sectorsize) + code_fileoff[0])
                                            if (datalenM > 0):
                                                if cmd == "encrypt":
                                                    for i in range(datalenM):
                                                        g.write(exefsctrmode2C.decrypt(
                                                            exefsctrmode.encrypt(f.read(1024*1024))))
                                                elif cmd == "decrypt":
                                                    for i in range(datalenM):
                                                        g.write(exefsctrmode2C.encrypt(
                                                            exefsctrmode.decrypt(f.read(1024*1024))))
                                                print(f"\rPartition {p:01} ExeFS: {cmd}ing: {exefs_filename[0].decode('UTF-8'):08}... {i:04} / {datalenM + 1:04} mb...")

                                            if (datalenB > 0):
                                                if cmd == "encrypt":
                                                    g.write(exefsctrmode2C.decrypt(
                                                        exefsctrmode.encrypt(f.read(datalenB))))
                                                elif cmd == "decrypt":
                                                    g.write(exefsctrmode2C.encrypt(
                                                        exefsctrmode.decrypt(f.read(datalenB))))
                                                print(f"\rPartition {p:01} ExeFS: {cmd}ing: {exefs_filename[0].decode('UTF-8'):08}... {datalenM + 1:04} / {datalenM + 1:04} mb... Done!")


                                if cmd == "encrypt":
                                    # encrypt exefs filename table
                                    process_exefs(cmd, f, g, part_off, exefs_off, sectorsize, exefsIV, NormalKey2C, p)

                                # encrypt exefs
                                exefsSizeM = int(
                                    (exefs_len[0] - 1) * sectorsize / (1024*1024))
                                exefsSizeB = (
                                    (exefs_len[0] - 1) * sectorsize) % (1024*1024)
                                ctroffset = int(sectorsize / 0x10)
                                exefsctr2C = Counter.new(
                                    128, initial_value=(exefsIV + ctroffset))
                                exefsctrmode2C = AES.new(
                                    NormalKey2C.to_bytes(16, 'big'), AES.MODE_CTR, counter=exefsctr2C)
                                f.seek(
                                    (part_off[0] + exefs_off[0] + 1) * sectorsize)
                                g.seek(
                                    (part_off[0] + exefs_off[0] + 1) * sectorsize)

                                if (exefsSizeM > 0):
                                    print("yes")
                                    for i in range(exefsSizeM):
                                        if cmd == "encrypt":
                                            g.write(exefsctrmode2C.encrypt(
                                                f.read(1024*1024)))
                                        elif cmd == "decrypt":
                                            g.write(exefsctrmode2C.decrypt(
                                                f.read(1024*1024)))
                                        print(f"\rPartition {p:01} ExeFS: {cmd}ing: {i:04} / {exefsSizeM + 1:04} mb", end=' ')
                                if (exefsSizeB > 0):
                                    if cmd == "encrypt":
                                        g.write(exefsctrmode2C.encrypt(
                                            f.read(exefsSizeB)))
                                    elif cmd == "decrypt":
                                        g.write(exefsctrmode2C.decrypt(
                                            f.read(exefsSizeB)))
                                    print(f"\rPartition {p:01} ExeFS: {cmd}ing: {exefsSizeM + 1:04} / {exefsSizeM + 1:04} mb... Done")
                            else:
                                print(f"Partition {p:01} ExeFS: No Data... Skipping...")

                            if (romfs_off[0] != 0):
                                romfsBlockSize = 16  # block size in mb
                                romfsSizeM = int(
                                    romfs_len[0] * sectorsize / (romfsBlockSize*(1024*1024)))
                                romfsSizeB = (
                                    romfs_len[0] * sectorsize) % (romfsBlockSize*(1024*1024))
                                romfsSizeTotalMb = (
                                    (romfs_len[0] * sectorsize) / (1024*1024) + 1)

                                if cmd == "encrypt":
                                    if (p > 0):  # RomFS for partitions 1 and up always use Key0x2C
                                        KeyX = KeyX = (KeyX0x2C[0]<<64) + KeyX0x2C[1]
                                        NormalKey = rol(
                                            (rol(KeyX, 2, 128) ^ KeyY) + Const, 87, 128)

                                romfsctr = Counter.new(
                                    128, initial_value=romfsIV)
                                romfsctrmode = AES.new(
                                    NormalKey.to_bytes(16, 'big'), AES.MODE_CTR, counter=romfsctr)

                                f.seek(
                                    (part_off[0] + romfs_off[0]) * sectorsize)
                                g.seek(
                                    (part_off[0] + romfs_off[0]) * sectorsize)
                                if (romfsSizeM > 0):
                                    for i in range(romfsSizeM):
                                        if cmd == "encrypt":
                                            g.write(romfsctrmode.encrypt(
                                                f.read(romfsBlockSize*(1024*1024))))
                                        elif cmd == "decrypt":
                                            g.write(romfsctrmode.decrypt(
                                                f.read(romfsBlockSize*(1024*1024))))
                                        print(f"\rPartition {p:01} RomFS: {cmd}ing: {i*romfsBlockSize:04} / {romfsSizeTotalMb:04} mb", end='\r')

                                if (romfsSizeB > 0):
                                    if cmd == "encrypt":
                                        g.write(romfsctrmode.encrypt(
                                            f.read(romfsSizeB)))
                                    elif cmd == "decrypt":
                                        g.write(romfsctrmode.decrypt(
                                            f.read(romfsSizeB)))

                                print(f"\rPartition {p:01} RomFS: {cmd}ing: {romfsSizeTotalMb:04} / {romfsSizeTotalMb:04} mb... Done", end='\r')

                            else:
                                print(f"Partition {p:01} RomFS: No Data... Skipping...")

                            g.seek((part_off[0] * sectorsize) + 0x18B)
                            if cmd == "encrypt":
                                if (p > 0):
                                    # for partitions 1 and up, set crypto-method to 0x00 (Key0x2C)
                                    g.write(struct.pack('<B', int(0x00)))
                                else:
                                    # if partition 0, restore crypto-method from backup_flags[3]
                                    g.write(struct.pack(
                                        '<B', int(backup_flags[3])))
                            elif cmd == "decrypt":
                                    # for partitions 1 and up, set crypto-method to 0x00 (Key0x2C)
                                    g.write(struct.pack('<B', int(0x00)))

                            g.seek((part_off[0] * sectorsize) + 0x18F)
                            if cmd == "decrypt":
                                g.write(struct.pack('<B', int(0x00)))
                                g.seek((part_off[0] * sectorsize) + 0x18F)
                            flag = int(partition_flags[7])
                            if cmd =="encrypt":
                                # turn off 0x01 = FixedCryptoKey and 0x20 = CryptoUsingNewKeyY and 0x04 = NoCrypto
                                flag = (flag & ((0x01 | 0x20 | 0x04) ^ 0xFF))
                                # set bits of crypto-method to backup flags[7] bits
                                flag = (flag | (0x01 | 0x20) & backup_flags[7])
                            elif cmd == "decrypt":
                                flag = (flag & ((0x01 | 0x20) ^ 0xFF))
                                flag = (flag | 0x04)  # turn on 0x04 = NoCrypto
                            g.write(struct.pack('<B', int(flag)))  # write flag

                        else:
                            print(("Partition %1d Unable to read NCCH header") % (p))
                    else:
                        print(("Partition %1d Not found... Skipping...") % (p))
                print("Done...")
            else:
                print("Error: Not a 3DS Rom?")


def main():
    parser = ArgumentParser(description="Encrypt/Decrypt 3DS Rom.")
    parser.add_argument(
        "cmd", choices=['encrypt', 'decrypt'], help="Whether to encrypt/decrypt.")
    parser.add_argument("file", help="Input file to encrypt/decrypt.")
    #parser.add_argument('-o', '--outfile', nargs='?')
    args = parser.parse_args()

    process(args.file, args.file, args.cmd)


if __name__ == '__main__':
    main()
