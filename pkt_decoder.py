import json
import pprint
from lora_packet import loraPacket
with open('pktlog_9.json') as data_file:
    pkts = json.load(data_file)

Nwkskey = 'A50C3284CDE7B92CF41467FC0017F923'
Appskey = '7F884D8284A3B1F454A31F4985EF9DB5'

#print(pkts[len(pkts)-1])
for i in range (0, len(pkts)):
    if pkts[i] != {} :
        pkt = loraPacket(pkts[i]['payload'])
        data = (pkt.decrypt(Appskey))
        
        bat = ((data[0] << 8 |data[1])*10)
        tempr = (data[2] << 8 | data[3])
        humid = (data[4] << 8 | data[5])
        pressure = (data[6] << 16 | data[7] << 8 | data[8] )
        lux = (data[9] << 8 | data[10])
        moist = (data[11] << 8 | data[12])
        #pkts[i]['bat'] = bat
        pkts[i].update(bat= bat, tempr = tempr, humid = humid, pressure = pressure, lux = lux, moisture = moist)
        print(data)

print(pkts[1])
with open('LoRa_data_dump_1.json','w') as dumpfile :
    json.dump(pkts,dumpfile,indent = 4, sort_keys = True)

   
            
    
