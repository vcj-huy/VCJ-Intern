#( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )
#( MACPayload = FHDR | FPort | FRMPayload )
#( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )

from lora.crypto import loramac_decrypt
from AES_CMAC import AES_CMAC
from Crypto.Cipher import AES
import math

class loraPacket(object):
    #PHYPayload = '0000000000000000000000000000000000001'
    
    def _hexStrEndianSwap(self,theString):
        """Rearranges character-couples in a little endian hex string to
        convert it into a big endian hex string and vice-versa. i.e. 'A3F2'
        is converted to 'F2A3'

        @param theString: The string to swap character-couples in
        @return: A hex string with swapped character-couples. -1 on error."""

        # We can't swap character couples in a string that has an odd number
        # of characters.
        if len(theString)%2 != 0:
            return -1

        # Swap the couples
        swapList = []
        for i in range(0, len(theString), 2):
            swapList.insert(0, theString[i:i+2])

        # Combine everything into one string. Don't use a delimeter.
        return ''.join(swapList)
    
    #( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )
    #( MACPayload = FHDR | FPort | FRMPayload )
    #( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )
    def __init__(self, payload):
        self.PHYPayload = payload
        self.MHDR = payload[0:2]
        self.MACPayload = payload[2:len(self.PHYPayload)-8]
        self.MIC = payload[len(self.PHYPayload)-8: len(self.PHYPayload)]
        self.DevAddr = self._hexStrEndianSwap(self.MACPayload[0:8])
        self.FCtrl = self.MACPayload[8:10]
        self.FCnt = int(self._hexStrEndianSwap(self.MACPayload[10:14]),16)
        self.FOptlen = int(self.FCtrl, 16) & 0b1111
        if (self.FOptlen > 0) :
            self.FOpts = self.MACPayload[14:14+self.FOptlen]
        else:
            self.FOpts = ''
            self.FPort = int(self.MACPayload[14:16])
            self.FRMPayload = self.MACPayload[16:len(self.MACPayload)] #encrypted data
    
    def decrypt(self, Appskey):
        return loramac_decrypt(self.FRMPayload, self.FCnt, Appskey, self.DevAddr, 0)
  
    def compute_mic(self, key, direction = 0):
        devaddr = unhexlify(self.MACPayload[0:8])
        fcnt = unhexlify(self.MACPayload[10:14])
        mic = [0x49]
        mic += [0x00, 0x00, 0x00, 0x00]
        mic += [direction]
        mic += devaddr
        mic += fcnt
        mic += [0x00]
        mic += [0x00]
        mic += [0x00]
        mic += [1 + self.mac_payload.length()]
        mic += [mhdr.to_raw()]
        mic += self.mac_payload.to_raw()

        cmac = AES_CMAC()
        computed_mic = cmac.encode(str(bytearray(key)), str(bytearray(mic)))[:4]
        return map(int, bytearray(computed_mic))
        
        
    
    
    
    
    
