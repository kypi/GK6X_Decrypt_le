
# Calculate CRC16. Got this from stack overflow :)
def crc16(data : bytearray, offset = 0, iv = 0xFFFF):
    length = len(data)
    if data is None or offset < 0 or offset > len(data)- 1 and offset+length > len(data):
        return 0
    crc = iv
    for i in range(0, length):
        crc ^= data[offset + i] << 8
        for j in range(0,8):
            if (crc & 0x8000) > 0:
                crc =(crc << 1) ^ 0x1021
            else:
                crc = crc << 1
        crc = crc & 0xFFFF # Only need 16 bits and prevents the CRC from growing on larger filesets
    return crc & 0xFFFF


# Based on decrypt function from pixeltris, but his function using a lookup table didn't work in python.
def decrypt2(buffer : bytearray,key):
    length = len(buffer)

    data_crc = 0xFFFF
    key_crc = key 
    buffer_mod = []
    for i in range(0, length):
        # Decryption step based on key CRC
        buffer_mod.append((buffer[i] ^ key_crc) & 0xFF)

        # Calculate key_crc for the next
        key_crc ^= buffer_mod[i] << 8

        for j in range(0,8):
            if (key_crc & 0x8000) > 0:
                key_crc =(key_crc << 1) ^ 0x1021
            else:
                key_crc = key_crc << 1
        key_crc = key_crc & 0xFFFF

        # Calcualte the data_crc for sanity checking against the one written in the file.
        data_crc ^= buffer_mod[i] << 8
        for j in range(0,8):
            if (data_crc & 0x8000) > 0:
                data_crc =(data_crc << 1) ^ 0x1021
            else:
                data_crc = data_crc << 1
        data_crc = data_crc & 0xFFFF

    # Return both the data crc and the decrypted data.
    return [data_crc,buffer_mod]


def decrypt_file(filename):
    print(f"Decrypting {filename}")
    f = open(filename, "rb")
    # First four bytes are header CRC

    # skip 4
    f.read(4)
    hcrc_bytes = f.read(4)
    header_crc = int.from_bytes(hcrc_bytes, byteorder='little', signed=True) 
    timestamp = f.read(4)
    data_length = int.from_bytes(f.read(4), byteorder='little', signed=True) 
    data_crc = int.from_bytes(f.read(4), byteorder='little', signed=False)  & 0xFFFF
    filetype = f.read(4)
    filetype_Str = f.read(8)

    # now we need to go through that to create an encryption key
    encryption_array = []
    for byte in filetype_Str:
        if byte == 0x00:
            break
        encryption_array.append(byte)

    # print(encryption_array)

    initial_key = crc16(encryption_array) & 0xFFFF
    encryption_key = crc16(filetype_Str,0, initial_key)

    # Read in the data:
    data = f.read(data_length)

    # Now decrypt the data using the encrpytion key (CRC16 XOR decrpytion)
    [file_calc, new_data] = decrypt2(data,encryption_key)

    # Double check the data CRC vs calculated data crc
    if(data_crc != file_calc):
        print("ERROR: Calculated CRC does not match file CRC. possible file corruption")

    # ======================================
    # Write the Decrypted data to a file.
    w = open("decrypted_" + filename, "wb")
    w.write(bytearray(new_data))
    w.close()
    # ======================================

    # Let's get the header:
    f.seek(0)
    headeri = f.read(32)

    # now let's calculate the CRC:
    header_list = list(headeri)
    header_list[4] = 0x00
    header_list[5] = 0
    header_list[6] = 0
    header_list[7] = 0
    header = bytearray(header_list)
    header_crc_calc = crc16(header)


    # Double check that the header CRC equals the calculated CRC:
    if(header_crc != header_crc_calc):
        print("Error: Header CRC does not match calculated CRC. there might be file corruption")

    f.close()


filename = "Glorious1.le"
decrypt_file(filename)