#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

##
## modified version of https://github.com/realoriginal/titanldr-ng/blob/master/python3/extract.py
##

STARDUST_END : bytes = b'STARDUST-END'

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser( description = 'Extracts shellcode from a PE.' )
        parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str )
        parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str )
        option = parser.parse_args()

        PeExe = pefile.PE( option.f )
        PeSec = PeExe.sections[0].get_data()

        if PeSec.find( STARDUST_END ) != None:
            ScRaw = PeSec[ : PeSec.find( STARDUST_END ) ]
            f = open( option.o, 'wb+' )
            f.write( ScRaw )
            f.close()
        else:
            print( '[!] error: no ending tag' )
    except Exception as e:
        print( '[!] error: {}'.format( e ) )
