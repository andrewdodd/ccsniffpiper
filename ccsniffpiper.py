#!/usr/bin/env python

"""

   ccsniffpiper - a python module to connect to the CC2531emk USB dongle
                 and pipe the sniffed packets to wireshark!
   Copyright (c) 2013, Andrew Dodd (andrew.john.dodd@gmail.com)

   This is essentially a mashup and extension of two existing sniffers:
   1. ccsniffer
   ------------
   Copyright (c) 2012, George Oikonomou (oikonomou@users.sf.net)

   2. sensniffer
   -------------
   Copyright (C) 2012 Christian Panton <christian@panton.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
"""

"""
   Functionality
   -------------
   Read IEEE802.15.4 frames from the default CC2531 EMK sniffer firmware
   and pipe them to wireshark via a FIFO/named pipe. At the same time, the
   frames can be logged to a file for subsequent offline processing.

   In interactive mode, the user can also input commands from stdin.
"""

import argparse
import os
import sys
import select
import time
import stat
import errno
import StringIO
import logging.handlers
import struct
import threading
import binascii
import usb.core
import usb.util
from locale import str

__version__ = '0.0.1'

defaults = {
    'hex_file': 'ccsniffpiper.hexdump',
    'out_fifo': '/tmp/ccsniffpiper',
    'pcap_file': 'ccsniffpiper.pcap',
    'debug_level': 'WARN',
    'log_level': 'INFO',
    'log_file': 'ccsniffpiper.log',
    'channel': 11,
}

logger = logging.getLogger(__name__)
stats = {}

class Frame(object):
    PCAP_FRAME_HDR_FMT = '<LLLL'

    def __init__(self, macPDUByteArray, timestampBy32):
        self.__macPDUByteArray = macPDUByteArray
        self.timestampBy32 = timestampBy32
        self.timestampUsec = timestampBy32 / 32.0
        self.len = len(self.__macPDUByteArray)

        self.__pcap_hdr = self.__generate_frame_hdr()

        self.pcap = self.__pcap_hdr + self.__macPDUByteArray
        self.hex = ''.join('%02x ' % ord(c) for c in self.__macPDUByteArray).rstrip()

    def __generate_frame_hdr(self):
        sec = 0
        usec = self.timestampUsec
        return struct.pack(Frame.PCAP_FRAME_HDR_FMT,
                           sec, usec, self.len, self.len)

    def get_pcap(self):
        return self.pcap

    def get_hex(self):
        return self.hex

    def get_timestamp(self):
        return self.timestampUsec

#####################################

class PCAPHelper:
    LINKTYPE_IEEE802_15_4_NOFCS = 230
    LINKTYPE_IEEE802_15_4 = 195
    MAGIC_NUMBER = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0
    SIGFIGS = 0
    SNAPLEN = 0xFFFF
    NETWORK = LINKTYPE_IEEE802_15_4

    PCAP_GLOBAL_HDR_FMT = '<LHHlLLL'

    @staticmethod
    def writeGlobalHeader():
        return struct.pack(
            PCAPHelper.PCAP_GLOBAL_HDR_FMT,
            PCAPHelper.MAGIC_NUMBER,
            PCAPHelper.VERSION_MAJOR,
            PCAPHelper.VERSION_MINOR,
            PCAPHelper.THISZONE,
            PCAPHelper.SIGFIGS,
            PCAPHelper.SNAPLEN,
            PCAPHelper.NETWORK)

class FifoHandler(object):
    def __init__(self, out_fifo):
        self.out_fifo = out_fifo
        self.of = None
        self.needs_pcap_hdr = True
        stats['Piped'] = 0
        stats['Not Piped'] = 0
        self.__create_fifo()

    def __create_fifo(self):
        try:
            os.mkfifo(self.out_fifo)
            logger.info('Opened FIFO %s' % (self.out_fifo,))
        except OSError as e:
            if e.errno == errno.EEXIST:
                if stat.S_ISFIFO(os.stat(self.out_fifo).st_mode) is False:
                    logger.error('File %s exists and is not a FIFO'
                                 % (self.out_fifo,))
                    sys.exit(1)
                else:
                    logger.warn('FIFO %s exists. Using it' % (self.out_fifo,))
            else:
                raise

    def __open_fifo(self):
        try:
            fd = os.open(self.out_fifo, os.O_NONBLOCK | os.O_WRONLY)
            self.of = os.fdopen(fd, 'w')
        except OSError as e:
            if e.errno == errno.ENXIO:
                logger.warn('Remote end not reading')
                stats['Not Piped'] += 1
                self.of = None
                self.needs_pcap_hdr = True
            elif e.errno == errno.ENOENT:
                logger.error('%s vanished under our feet' % (self.out_fifo,))
                logger.error('Trying to re-create it')
                self.__create_fifo_file()
                self.of = None
                self.needs_pcap_hdr = True
            else:
                raise

    def triggerNewGlobalHeader(self):
        self.needs_pcap_hdr = True

    def handle(self, data):
        if self.of is None:
            self.__open_fifo()

        if self.of is not None:
            try:
                if self.needs_pcap_hdr is True:
                    self.of.write(PCAPHelper.writeGlobalHeader())
                    self.needs_pcap_hdr = False
                self.of.write(data.pcap)
                self.of.flush()
                logger.debug('Wrote a frame of size %d bytes' % (data.len))
                stats['Piped'] += 1
            except IOError as e:
                if e.errno == errno.EPIPE:
                    logger.info('Remote end stopped reading')
                    stats['Not Piped'] += 1
                    self.of = None
                    self.needs_pcap_hdr = True
                else:
                    raise
#####################################
class PcapDumpHandler(object):
    def __init__(self, filename):
        self.filename = filename
        stats['Dumped to PCAP'] = 0

        try:
            self.of = open(self.filename, 'w')
            self.of.write(PCAPHelper.writeGlobalHeader())
            logger.info("Dumping PCAP to %s" % (self.filename,))
        except IOError as e:
            self.of = None
            logger.warn("Error opening %s to save pcap. Skipping"
                         % (self.filename))
            logger.warn("The error was: %d - %s"
                         % (e.args))

    def handle(self, frame):
        if self.of is None:
            return
        self.of.write(frame.get_pcap())
        self.of.flush()
        logger.info('PcapDumpHandler: Dumped a frame of size %d bytes'
                     % (frame.len))
        stats['Dumped to PCAP'] += 1

class HexdumpHandler(object):
    def __init__(self, filename):
        self.filename = filename
        stats['Dumped as Hex'] = 0
        try:
            self.of = open(self.filename, 'wb')
            logger.info("Dumping hex to %s" % (self.filename,))
        except IOError as e:
            logger.warn("Error opening %s for hex dumps. Skipping"
                         % (self.filename))
            logger.warn("The error was: %d - %s" % (e.args))
            self.of = None

    def handle(self, frame):
        if self.of is None:
            return

        try:
            # Prepend the original timestamp in big-endian format
            self.of.write(binascii.hexlify(struct.pack(">I ", frame.get_timestamp()*32)))
            #self.of.write(str(frame.get_timestamp()))
            self.of.write("  ")
#             self.of.write('0000 ')
            self.of.write(frame.get_hex())
            self.of.write('\n')
            self.of.flush()
            stats['Dumped as Hex'] += 1
            logger.info('HexdumpHandler: Dumped a frame of size %d bytes'
                         % (frame.len))
        except IOError as e:
            logger.warn("Error writing hex to %s for hex dumps. Skipping"
                     % (self.of))
            logger.warn("The error was: %d - %s" % (e.args))

class CC2531:

    DEFAULT_CHANNEL = 0x0B # 11

    DATA_EP = 0x83
    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN  = 0xc0

    GET_IDENT = 0xc0
    SET_POWER = 0xc5
    GET_POWER = 0xc6

    SET_START = 0xd0 # bulk in starts
    SET_STOP  = 0xd1 # bulk in stops
    SET_CHAN  = 0xd2 # 0x0d (idx 0) + data)0x00 (idx 1)

    COMMAND_FRAME = 0x00
#     COMMAND_CHANNEL = ??

    def __init__(self, callback, channel = DEFAULT_CHANNEL):

        stats['Captured'] = 0
        stats['Non-Frame'] = 0

        self.dev = None
        self.channel = channel
        self.callback = callback
        self.thread = None
        self.running = False

        try:
            self.dev = usb.core.find(idVendor=0x0451, idProduct=0x16ae)
        except usb.core.USBError:
            raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)

        if self.dev is None:
            raise IOError("Device not found")

        self.dev.set_configuration() # must call this to establish the USB's "Config"
        self.name = usb.util.get_string(self.dev, 256, 2) # get name from USB descriptor
        self.ident = self.dev.ctrl_transfer(CC2531.DIR_IN, CC2531.GET_IDENT, 0, 0, 256) # get identity from Firmware command

        # power on radio, wIndex = 4
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_POWER, wIndex=4)

        while True:
            # check if powered up
            power_status = self.dev.ctrl_transfer(CC2531.DIR_IN, CC2531.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        self.set_channel(channel)

    def __del__(self):
        if self.dev:
            # power off radio, wIndex = 0
            self.dev.ctrl_transfer(self.DIR_OUT, self.SET_POWER, wIndex=0)

    def start(self):
        # start sniffing
        self.running = True
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_START)
        self.thread = threading.Thread(target=self.recv)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        # end sniffing
        self.running = False
        self.thread.join()
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_STOP)

    def isRunning(self):
        return self.running

    def recv(self):

        while self.running:
            try:
                bytesteam = self.dev.read(CC2531.DATA_EP, 4096, timeout=CC2531.DATA_TIMEOUT)
            except usb.core.USBError as e:
                # error 110 is timeout, just ignore, next read might work again
                if e.errno == 110:
                    continue
                else:
                    raise e

#             print "RECV>> %s" % binascii.hexlify(bytesteam)

            if len(bytesteam) >= 3:
                (cmd, cmdLen) = struct.unpack_from("<BH", bytesteam)
                bytesteam = bytesteam[3:]
                if len(bytesteam) == cmdLen:
                    # buffer contains the correct number of bytes
                    if CC2531.COMMAND_FRAME == cmd:
                        logger.info('Read a frame of size %d' % (cmdLen,))
                        stats['Captured'] += 1
                        (timestamp, pktLen) = struct.unpack_from("<IB", bytesteam)
                        frame = bytesteam[5:]

                        if len(frame) == pktLen:
                            self.callback(timestamp, frame.tostring())
                        else:
                            logger.warn("Received a frame with incorrect length, pkgLen:%d, len(frame):%d" %(pktLen, len(frame)))

#                     elif cmd == CC2531.COMMAND_CHANNEL:
#                         logger.info('Received a command response: [%02x %02x]' % (cmd, bytesteam[0]))
#                         # We'll only ever see this if the user asked for it, so we are
#                         # running interactive. Print away
#                         print 'Sniffing in channel: %d' % (bytesteam[0],)
                    else:
                        logger.warn("Received a command response with unknown code - CMD:%02x byte:%02x]" % (cmd, bytesteam[0]))


    def set_channel(self, channel):
        was_running = self.running

        if channel >= 11 and channel <= 26:
            if self.running:
                self.stop()

            self.channel = channel

            # set channel command
            self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_CHAN, 0, 0, [channel])
            self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_CHAN, 0, 1, [0x00])

            self.get_channel()

            if was_running:
                self.start()

        else:
            raise ValueError("Channel must be between 11 and 26")

    def get_channel(self):
        return self.channel

    def __repr__(self):

        if self.dev:
            return "%s <Channel: %d>" % (self.name, self.channel)
        else:
            return "Not connected"


def arg_parser():
    debug_choices = ('DEBUG', 'INFO', 'WARN', 'ERROR')

    parser = argparse.ArgumentParser(add_help = False,
                                     description = 'Read IEEE802.15.4 frames \
    from a CC2531 packet sniffer device, convert them to pcap and pipe them \
    into wireshark over a FIFO pipe for online analysis. Frames \
    can also be saved in a file in hexdump and/or pcap format for offline \
    analysis.')

    in_group = parser.add_argument_group('Input Options')
    in_group.add_argument('-c', '--channel', type = int, action = 'store',
                          choices = range(11, 27),
                          default = defaults['channel'],
                          help = 'Set the sniffer\'s CHANNEL. Valid range: 11-26. \
                                  (Default: %s)' % (defaults['channel'],))
    out_group = parser.add_argument_group('Output Options')
    out_group.add_argument('-f', '--fifo', action = 'store',
                           default = defaults['out_fifo'],
                           help = 'Set FIFO as the named pipe for sending to wireshark. \
                                   If argument is omitted and -o option is not specified \
                                   the capture will pipe to: %s' % (defaults['out_fifo'],))
    out_group.add_argument('-o', '--offline', action = 'store_true',
                           default = False,
                           help = 'Disables sending the capture to the named pipe.')
    out_group.add_argument('-x', '--hex-file', action = 'store', nargs = '?',
                           const = defaults['hex_file'], default = False,
                           help = 'Save the capture (hexdump) in HEX_FILE. \
                                   If -x is specified but HEX_FILE is omitted, \
                                   %s will be used. If the argument is \
                                   omitted altogether, the capture will not \
                                   be saved.' % (defaults['hex_file'],))
    out_group.add_argument('-p', '--pcap-file', action = 'store', nargs = '?',
                           const = defaults['pcap_file'], default = False,
                           help = 'Save the capture (pcap format) in PCAP_FILE. \
                                   If -p is specified but PCAP_FILE is omitted, \
                                   %s will be used. If the argument is \
                                   omitted altogether, the capture will not \
                                   be saved.' % (defaults['pcap_file'],))


    log_group = parser.add_argument_group('Verbosity and Logging')
    log_group.add_argument('-d', '--headless', action = 'store_true',
                           default = False,
                           help = 'Run in non-interactive/headless mode, without \
                                   accepting user input. (Default Disabled)')
    log_group.add_argument('-D', '--debug-level', action = 'store',
                           choices = debug_choices,
                           default = defaults['debug_level'],
                           help = 'Print messages of severity DEBUG_LEVEL \
                                   or higher (Default %s)'
                                   % (defaults['debug_level'],))
    log_group.add_argument('-L', '--log-file', action = 'store', nargs = '?',
                           const = defaults['log_file'], default = False,
                           help = 'Log output in LOG_FILE. If -L is specified \
                                   but LOG_FILE is omitted, %s will be used. \
                                   If the argument is omitted altogether, \
                                   logging will not take place at all.'
                                   % (defaults['log_file'],))
    log_group.add_argument('-l', '--log-level', action = 'store',
                           choices = debug_choices,
                           default = defaults['log_level'],
                           help = 'Log messages of severity LOG_LEVEL or \
                                   higher. Only makes sense if -L is also \
                                   specified (Default %s)'
                                   % (defaults['log_level'],))

    gen_group = parser.add_argument_group('General Options')
    gen_group.add_argument('-v', '--version', action = 'version',
                           version = 'ccsniffpiper v%s' % (__version__))
    gen_group.add_argument('-h', '--help', action = 'help',
                           help = 'Shows this message and exits')

    return parser.parse_args()

def dump_stats():
    s = StringIO.StringIO()

    s.write('Frame Stats:\n')
    for k, v in stats.items():
        s.write('%20s: %d\n' % (k, v))

    print(s.getvalue())

def log_init():
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, args.debug_level))
    cf = logging.Formatter('%(message)s')
    ch.setFormatter(cf)
    logger.addHandler(ch)

    if args.log_file is not False:
        fh = logging.handlers.RotatingFileHandler(filename = args.log_file,
                                                  maxBytes = 5000000)
        fh.setLevel(getattr(logging, args.log_level))
        ff = logging.Formatter(
            '%(asctime)s - %(levelname)8s - %(message)s')
        fh.setFormatter(ff)
        logger.addHandler(fh)

if __name__ == '__main__':
    args = arg_parser()
    log_init()

    logger.info('Started logging')

    handlers = []

    def handlerDispatcher(timestamp, macPDU):
        """ Dispatches any received frames to all registered handlers

            timestamp -> The timestamp the frame was received, as reported by the sniffer device, in microseconds
            macPDU -> The 802.15.4 MAC-layer PDU, starting with the Frame Control Field (FCF)
        """
        if len(macPDU) > 0:
            frame = Frame(macPDU, timestamp)
            for h in handlers:
                h.handle(frame)


    if args.offline is not True:
        f = FifoHandler(out_fifo = args.fifo)
        handlers.append(f)
    if args.hex_file is not False:
        handlers.append(HexdumpHandler(args.hex_file))
    if args.pcap_file is not False:
        handlers.append(PcapDumpHandler(args.pcap_file))

    if args.headless is False:
        h = StringIO.StringIO()
        h.write('Commands:\n')
        h.write('c: Print current RF Channel\n')
        h.write('n: Trigger new pcap header before the next frame\n')
        h.write('h,?: Print this message\n')
        h.write('[11,26]: Change RF channel\n')
        h.write('s: Start/stop the packet capture\n')
        h.write('q: Quit')
        h = h.getvalue()

        e = 'Unknown Command. Type h or ? for help'

        print h

    snifferDev = CC2531(handlerDispatcher, args.channel)
    try:

        while 1:
            if args.headless is True and not snifferDev.isRunning():
                snifferDev.start()
            else:
                try:
                    if select.select([sys.stdin, ], [], [], 10.0)[0]:
                        cmd = sys.stdin.readline().rstrip()
                        logger.debug('User input: "%s"' % (cmd,))
                        if cmd in ('h', '?'):
                            print h
                        elif cmd == 'c':
                            # We'll only ever see this if the user asked for it, so we are
                            # running interactive. Print away
                            print 'Sniffing in channel: %d' % (snifferDev.get_channel(),)
                        elif cmd == 'n':
                            f.triggerNewGlobalHeader()
                        elif cmd == 'q':
                            logger.info('User requested shutdown')
                            sys.exit(0)
                        elif cmd == 's':
                            if snifferDev.isRunning():
                                snifferDev.stop()
                            else:
                                snifferDev.start()
                        elif int(cmd) in range(11, 27):
                            snifferDev.set_channel(int(cmd))
                        else:
                            raise ValueError
#                    else:
#                        logger.debug('No user input')
                except select.error:
                    logger.warn('Error while trying to read stdin')
                except ValueError:
                    print e
                except UnboundLocalError:
                    # Raised by command 'n' when -o was specified at command line
                    pass

    except (KeyboardInterrupt, SystemExit):
        logger.info('Shutting down')
        if snifferDev.isRunning():
            snifferDev.stop()
        dump_stats()
        sys.exit(0)

