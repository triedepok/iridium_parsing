#!/usr/bin/env python
import os
import time
from datetime import date, datetime, timedelta
import pytz
import sys
import re
import bitstruct

#################################################
# Update    : 13-05-2020 00:12:00
# Create By : triedepok@gmail.com
# bug report
# 
# 28-12-2019 - error socket
# 10-01-2020 - Tambah fungsi parsing SBD
# 15-03-2020 - message 2 tidak diproses
# 20-03-2020 - Tambah fungsi mail_text_data dan mail_text_term
# 08-05-2020 - Add Decode Encode data CBT
# 13-05-2020 - Add Decode Encode sensor BPR and Accelero
#################################################

class Isbdmsg:
    def __init__(self,data=None):
        self.load(data)

    def load(self,data):
        self.entire_isbd_msg= data
        self.unpack()

    def unpack(self):
        import struct
        import binascii
        if self.entire_isbd_msg:
            l=len(self.entire_isbd_msg) # Or `self.total_msg_len` might work. Should check that.
            packformat= '>cHcHIccccccccccccccccHHIcHccHcHIcH' + 'c'*(l-51)
            m= list(struct.unpack(packformat,self.entire_isbd_msg)) # m is message component list.
            for n in [0,2,20,24,32]: # For these fields...
                m[n]= binascii.hexlify(m[n])               # ...fix binary coded numbers to be proper numbers.
            for n in [26,27,29]:
                m[n]= ord(m[n])                            # Byte to int values for location orient and degrees
        else:
            m= [None for N in range(35)] # At least 35 components.
        self.msg_protocol_ver   = m[0]  # Should always equal 1.
        self.total_msg_len      = m[1]  # Number of bytes sent by ISBD.
        self.mo_header_iei      = m[2]  # Should always equal 1.
        self.mo_header_len      = m[3]  # Should always equal 28.
        self.cdr_ref            = m[4]  # Call Detail Record Reference. An automatic ID number.
        if m[5]:                        # Only if the data is ready 
            self.imei           = ''.join(m[5:20]) # IMEI Unit Identification.
        else:
            self.imei           = None  # The whole field is set to None.
        self.status             = m[20] # Session status - 0=success; 1&2 also mostly ok.; 10,12-15=problem
        self.momsn              = m[21] # Mobile Originated Message Sequence Number.
        self.mtmsn              = m[22] # Mobile Terminated Message Sequence Number. Should equal 0.
        self.msg_timestamp      = m[23] # Time Iridium sees msg (not unit generated or arrival). Seconds since epoch.
        self.payload_header_iei = m[24] # Should always equal 3.
        self.payload_header_len = m[25] # Should always be 11.
        self.loc_orient         = m[26] # Location orientation code (0=N,E; 1=N,W; 2=S,E; 3=S,W).
        self.loc_lat_deg        = m[27] # Latitude - degree part.
        self.loc_lat_min        = m[28] # Latitude - minute part.
        self.loc_lon_deg        = m[29] # Longitude - degree part.
        self.loc_lon_min        = m[30] # Longitude - minute part.
        self.cep_radius         = m[31] # Circular Error Probable (CEP) Radius.
        self.payload_iei        = m[32] # Start of Payload IEI type. Should always equal 2.
        self.payload_len        = m[33] # Length of this payload
        if m[34]:
            self.payload        = ''.join(m[34:]) # The actual message sent from the unit, bit for bit.
            self.payload_hex    = binascii.hexlify(self.payload) # Printable hex _string_ of payload.
        else:
            self.payload        = None
            self.payload_hex    = None
        return self
    
    def read_sbd_file(self,filename):
        try:
            f= open(filename,'rb')
            self.entire_isbd_msg= f.read()
            f.close()
        except IOError:
            print "IOError reading file %s." % filename
        self.unpack()
        return self

    def write_sbd_file(self,filename):
        import os
        try:
            d= os.path.dirname(filename)
            if not os.path.exists(d):
                os.makedirs(d)
            f= open(filename,'wb')
            f.write(self.entire_isbd_msg)
            f.close()
        except IOError:
            print "IOError writing file %s." % filename

    def dated_filename(self,basedir,bonus=''):
        subdir= self.timestamp_fmt('justdate')
        if not subdir:
            subdir= "unknown"
        return '%s/%s/%s-%s%s.sbd'%(basedir,subdir,self.timestamp_fmt(),self.imei,bonus)

    def timestamp_fmt(self,style='log'):
        t= self.msg_timestamp
        if not t: return None
        import datetime
        if style == 'log':
            return datetime.datetime.fromtimestamp(t).strftime("%Y%m%d%H%M%S")
        elif style == 'justdate':
            return datetime.datetime.fromtimestamp(t).strftime("%Y%m%d")
        elif style == 'iso8601':
            return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif style == 'mysql':
            return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        return None

    def location_fmt(self,style="human"):
        o= self.loc_orient
        ladeg= self.loc_lat_deg
        lamin= self.loc_lat_min * .001
        lodeg= self.loc_lon_deg
        lomin= self.loc_lon_min * .001
        ladir,lodir= "+-","+-"
        ladir=ladir[o & 2 and 1]
        lodir=lodir[o & 1]
        la= ladir + '%.6f'%(ladeg+lamin/60.0)
        lo= lodir + '%.6f'%(lodeg+lomin/60.0)
        if style == 'svg':
            return '<circle r="1px"  cx="%s" cy="%s" />' % (lo,la)
        elif style == 'lat':
            return float(la)
        elif style == 'lon':
            return float(lo)
        elif style == 'iso6709':
            pass
        elif style == 'google': # http://maps.google.com/maps?q=-37.771008,-122.412175
            pass
        elif style == 'log': # E.g. +6d46.945'+138d15.134'
            return "%s%sd%.3f'%s%sd%.3f'"%(ladir,ladeg,lamin,lodir,lodeg,lomin)
        elif style == 'human':
            return 'lat: %s, lon: %s' % (lo,la)
    
    def send_as_socket_client(self,con):
        import socket
        try:
            s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(con)
            s.send(self.entire_isbd_msg)
            s.close()
        except socket.error as msg:
            return 'ERROR: ISBD socket client failed! %s (error #%s)' % (msg[1],str(msg[0]))
        return True

class tews():
    def __init__(self,data=None):
        self.payload = data
    
    def hex2bin(self):
        """Convert a hexdecimal string to binary string, with zero fillings. """
        num_of_bits = len(self.payload) * 4
        self.msg_bin = bin(int(self.payload, 16))[2:].zfill(int(num_of_bits))
        return self
    
    def bin2int(self,binstr):
        """Convert a binary string to integer. """
        return int(binstr, 2)
    
    def hex2int(self,hexstr):
        """Convert a hexdecimal string to integer. """
        return int(hexstr, 16)  
    
    def bin2coordinat(self,binstr1,binstr2):
        hasil = int(binstr2, 2)
        if(self.bin2int(binstr1[0])==False):
            hasil = hasil * -1
        hasil = round(float(hasil),6)/1000000
        return hasil
    
    def get_date(self,dateFormat="%d-%m-%Y", addDays=0):
        timeNow = datetime.now()
        if (addDays!=0):
            anotherTime = timeNow + timedelta(days=addDays)
        else:
            anotherTime = timeNow
        return anotherTime.strftime(dateFormat)
    
    def new_date(self,waktu, dateFormat="%d-%m-%Y", addDays=0):
        timeNow = datetime.now()
        if (addDays!=0):
            anotherTime = waktu + timedelta(days=addDays)
        else:
            anotherTime = waktu
        return anotherTime.strftime(dateFormat)
    def tstamp_to_dtime(self,timestamp):
        return datetime.utcfromtimestamp(timestamp)
    
    def utc_to_local(self,utc_dt):
        local_tz = pytz.timezone('Asia/Jakarta')
        local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
        return (local_tz.normalize(local_dt).strftime('%Y-%m-%d %H:%M:%S'))
    
    def tews_msg_id(self):
        self.payload
        self.hex2bin()
        self.msg_id     = self.bin2int(self.msg_bin[0:3])             #3  bit
        return self
    
    def tews_decode_text(self):
        data              = self.payload
        self.hex_data     = data.encode('hex')
        self.hex2bin()
        return self
    
    def is_ascii(self,text):
        if isinstance(text, unicode):
            try:
                text.encode('ascii')
            except UnicodeEncodeError:
                return False
        else:
            try:
                text.decode('ascii')
            except UnicodeDecodeError:
                return False
        return True
    
    def tews_decode_msg0_1(self):
        self.buoy_id   = self.bin2int(self.msg_bin[3:11])        #8  bit
        self.waktu     = self.bin2int(self.msg_bin[11:28])       #17 bit
        self.data1     = self.bin2int(self.msg_bin[28:48])       #20 bit
        self.data2     = self.bin2int(self.msg_bin[48:63])       #15 bit
        self.data3     = self.bin2int(self.msg_bin[63:78])       #15 bit
        self.data4     = self.bin2int(self.msg_bin[78:93])       #15 bit
        self.obu       = self.bin2int(self.msg_bin[93:95])       #2  bit
        self.acce      = self.bin2int(self.msg_bin[95:96])       #1  bit
        return self
    
    def tews_decode_msg0_1_ver2(self):
        self.buoy_id   = self.bin2int(self.msg_bin[3:11])        #8  bit
        self.waktu     = self.bin2int(self.msg_bin[11:28])       #17 bit
        self.data1     = self.bin2int(self.msg_bin[28:48])       #20 bit
        self.data2     = self.bin2int(self.msg_bin[48:63])       #15 bit
        self.data3     = self.bin2int(self.msg_bin[63:78])       #15 bit
        self.data4     = self.bin2int(self.msg_bin[78:93])       #15 bit
        self.mode      = self.bin2int(self.msg_bin[93:94])       #1  bit
        self.obu       = self.bin2int(self.msg_bin[94:95])       #1  bit
        self.acce      = self.bin2int(self.msg_bin[95:96])       #1  bit
        return self
    
    def tews_decode_msg2(self):
        self.buoy_id      = self.bin2int(self.msg_bin[3:11])        #8  bit
        self.waktu        = self.bin2int(self.msg_bin[11:28])       #17 bit
        self.bat_buoy     = self.bin2int(self.msg_bin[28:40])       #12 bit
        self.bat_obu      = self.bin2int(self.msg_bin[40:52])       #12 bit
        self.reserved     = self.bin2int(self.msg_bin[52:56])       #4  bit
        return self
    
    def tews_decode_msg3(self):
        self.buoy_id      = self.bin2int(self.msg_bin[3:11])                        #8  bit
        self.waktu        = self.bin2int(self.msg_bin[11:28])                       #17 bit
        self.lat          = self.bin2coordinat(self.msg_bin[28:29],self.msg_bin[29:56])      #1  bit 27  bit
        self.lon          = self.bin2coordinat(self.msg_bin[56:57],self.msg_bin[57:85])      #1  bit 28  bit
        self.reserved     = self.bin2int(self.msg_bin[85:88])                       #3  bit
        return self
    
    def decode_mqtt(self):
        packformat    = 'u10s32u26s16s20s20s20'
        cf            = bitstruct.compile(packformat)
        msg           = self.payload
        hasil         = cf.unpack(msg)
        self.id       = int(hasil[0])
        self.waktu    = self.todatetimes(hasil[1])
        self.press    = float(hasil[2])/100
        self.temp     = float(hasil[3])/100
        self.acl_x    = float(hasil[4])/100
        self.acl_y    = float(hasil[5])/100
        self.acl_z    = float(hasil[6])/100
        return self
    
    def decode_mqtt_bpr(self):
        bpr           = bitstruct.compile('u10u2s32u28s16')     #11 byte
        msg           = self.payload
        hasil         = bpr.unpack(msg)
        self.no       = int(hasil[0])
        self.tipe     = int(hasil[1])
        self.waktu    = self.todatetimes(hasil[2])
        self.press    = float(hasil[3])/100
        self.temp     = float(hasil[4])/100
        return self
    
    def decode_mqtt_acl(self):
        acl           = bitstruct.compile('u10u2s32s20s20s20')  #13 byte
        msg           = self.payload
        hasil         = acl.unpack(msg)
        self.no       = int(hasil[0])
        self.tipe     = int(hasil[1])
        self.waktu    = self.todatetimes(hasil[2])
        self.acl_x    = float(hasil[3])/100
        self.acl_y    = float(hasil[4])/100
        self.acl_z    = float(hasil[5])/100
        return self
    
    def totimestamp(self, dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        # return td.total_seconds()
        return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6
    
    def todatetimes(self, ts, frm='%Y-%m-%d %H:%M:%S'):
        return datetime.utcfromtimestamp(ts).strftime(frm)
    
    def mail_text_data(self):
        msg      = self.payload
        MOMSN    = msg.splitlines()[0].split()
        MTMSN    = msg.splitlines()[1].split()
        waktu    = msg.splitlines()[2].split()
        MSize    = msg.splitlines()[4].split()
        kordinat = msg.splitlines()[6].split()
        CEP      = msg.splitlines()[7].split()
        if(MOMSN[0]=="MOMSN:" and MSize[0]=="Message" and waktu[0] == "Time" and waktu[3]=="(UTC):" and kordinat[2] == "Lat" and kordinat[5]=="Long" and CEP[0]=="CEPradius"):
            waktu_      = ("%s-%s-%s %s" % (int(waktu[6]),waktu[5],waktu[8],waktu[7]))
            waktu_utc   = datetime.strptime(waktu_, '%d-%b-%Y %H:%M:%S')
            waktu_local = datetime.strptime(self.utc_to_local(waktu_utc), '%Y-%m-%d %H:%M:%S')
            self.waktu_utc      = waktu_utc
            self.msize          = MSize[3]
            self.momsn          = MOMSN[1]
            self.mtmsn          = MTMSN[1]
            self.ce_pradius     = CEP[2]
            self.lat            = kordinat[4]
            self.lon            = kordinat[7]
            return self
    
    def mail_text_term(self):
        msg         = self.payload
        imei        = msg.splitlines()[2].split()
        waktu       = msg.splitlines()[3].split()
        mtmsn       = msg.splitlines()[8].split()
        waktu_      = ("%s-%s-%s %s" % (int(waktu[3]),waktu[2],waktu[5],waktu[4]))
        waktu_utc   = datetime.strptime(waktu_, '%d-%b-%Y %H:%M:%S')
        waktu_local = datetime.strptime(self.utc_to_local(waktu_utc), '%Y-%m-%d %H:%M:%S')
        
        self.imei           = imei[1]
        self.waktu_utc      = waktu_utc
        self.mtmsn          = re.sub('[!@#$,]', '', mtmsn[3])
        return self
