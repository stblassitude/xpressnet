#!/usr/bin/env python

import logging
import struct
import sys

from enum import IntEnum
from functools import reduce
from socket import socket, timeout, AF_INET, SOCK_STREAM


class Command(IntEnum):
    """
    Command and response identifiers. Note that this is encoded in the header byte, with the command code being
    the upper nibble, and the number of bytes in the message the lower nibble. To avoid confusion, this enum is defined
    as a whole byte, with values from 0x00 to 0xF0.
    """
    INTERFACE_STATUS = 0x00
    PROGRAMMING = 0x20
    ACCESSORY_REPORT = 0x40
    ACCESSORY_CONTROL = 0x50
    STATUS = 0x60
    ALL_LOCOS = 0x80
    LOCO = 0xE0
    INTERFACE = 0xF0

    def __repr__(self):
        return self.value


class Status(IntEnum):
    """
    Commands will receive certain status responses. See page 7, section 1.5 (header code 0x00),
    and page 16, section 3.1.2 (header code 0x60)
    """
    OK = 0x00
    WRONG_NUMBER_OF_BYTES = 0x01
    TIMEOUT = 0x02
    SENT = 0x04
    NOT_ADDRESSING = 0x05
    BUFFER_OVERFLOW = 0x06
    ADDRESSING_AGAIN = 0x07
    UNABLE_TO_RECEIVE = 0x08
    INVALID_PARAMETER = 0x09
    UNKNOWN_ERROR = 0x0A
    READY = 0x11
    SHORT_CIRCUIT = 0x12
    NOT_FOUND = 0x13
    BUSY = 0x1F


class AccessoryKind(IntEnum):
    OUTPUT_WITHOUT_FEEDBACK = 0
    OUTPUT_WITH_FEEDBACK = 1
    INPUT = 2
    RESERVED = 3


class AccessoryStateMessage:
    def __init__(self, bytes=None):
        self.address = 0
        self.undetermined = True
        self.kind = AccessoryKind.RESERVED
        self.nibble = 0
        self.state = [0, 0, 0, 0]

        if bytes is not None:
            self.address = bytes[0]
            self.undetermined = bytes[1] & 0b1000000 != 0
            self.kind = AccessoryKind(bytes[1] >> 5 & 0b11)
            self.nibble = (bytes[1] >> 4) & 0b1
            self.state = list(1 if ((bytes[1] & (1 << i)) != 0) else 0 for i in range(4))
            # self.state = list(i for i in range(3))

    def __repr__(self):
        return f"{type(self).__name__}<addr={self.address}, {self.kind}, nibble={self.nibble}, {self.state}>"


class TrackStatus(IntEnum):
    TRACK_OFF = 0x00,
    TRACK_ON = 0x01,
    PROGRAMMING = 0x02


class TrackStatusMessage:
    def __init__(self, state):
        self.state = TrackStatus(state)

    def __repr__(self):
        return f"{type(self).__name__}<{str(self.state)}>"

class XpressNetException(Exception):
    pass


class XpressNetCommandResult:
    def __init__(self, code, status, data=None):
        self.code = Command(code)
        self.status = Status(status)
        self.data = data if data else bytearray()

    def __repr__(self):
        return f"{type(self).__name__}<{str(self.code)}({str(self.status)})>"


class XpressNetProgrammingResult:
    def __init__(self, cv, value):
        self.cv = cv
        self.value = value


class XpressNet:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.last_broadcast = None
        self.debug_line = False
        self.track_status = TrackStatus.TRACK_OFF

    def open(self):
        logging.debug("Opening connection")
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(1.0)
        try:
            self.sock.recv(512)  # flush any remaining unread data
        except timeout:
            pass
        self.sock.settimeout(None)

    def close(self):
        logging.debug("Closing connection")
        self.sock.close()

    def send(self, data):
        buffer = bytearray([0xFF, 0xFE])
        buffer.extend(data)
        buffer.append(reduce(lambda r, v: r ^ v, data))
        if self.debug_line:
            logging.debug(f"Sending {len(buffer)}: {self.__hex(buffer)}")
        self.sock.send(buffer)

    def __read(self, length):
        data = bytearray()
        while len(data) < length:
            data += self.sock.recv(length - len(data))
        if self.debug_line:
            logging.debug(f"Received {len(data)}: {self.__hex(data)}")
        return data

    def __get_status(self, cmd, is_broadcast, code, length, data):
        # response is a regular message
        if code == Command.INTERFACE_STATUS:
            # communication error: page 7, section 1.5
            # interface version number: page 9, section 1.6
            if cmd == Command.INTERFACE:
                return XpressNetCommandResult(code, Status.OK, data)
            if len(data) != 1:
                raise XpressNetException(f"unexpected response data 0x{self.__hex(data)}")
            return XpressNetCommandResult(code, data[0])
        elif code == Command.STATUS:
            if is_broadcast:
                if len(data) != 1:
                    raise XpressNetException(f"Unknown response 0x{self.__hex(data)}")
                return TrackStatusMessage(data[0])
            if not len(data) == 3:
                raise XpressNetException(f"Invalid programming response 0x{self.__hex(data)}")
            (subcode, cv, value) = data[0:3]
            if subcode == 0x10:
                # programming mode response data 3 bytes: page 17, section 3.1.2.5
                return XpressNetProgrammingResult(cv, value)
            elif subcode == 0x14:
                # programming mode response data 4 bytes, CV 1-255, CV1024: page 18, section 3.1.2.6
                if cv == 0:
                    return XpressNetProgrammingResult(1024, value)
                else:
                    return XpressNetProgrammingResult(cv, value)
            elif subcode == 0x15:
                # programming mode response data 4 bytes, CV 256-511: page 19, section 3.1.2.7
                return XpressNetProgrammingResult(cv + 256, value)
            elif subcode == 0x16:
                # programming mode response data 4 bytes, CV 512-767: page 19, section 3.1.2.8
                return XpressNetProgrammingResult(cv + 512, value)
            elif subcode == 0x17:
                # programming mode response data 4 bytes, CV 768-1023: page 20, section 3.1.2.9
                return XpressNetProgrammingResult(cv + 768, value)
            else:
                raise XpressNetException(f"Unknown programming response code 0x{code:02X}/{subcode:02X}")
        elif code == Command.INTERFACE:
            (subcode,) = data[0:1]
            if subcode in (0x01, 0x02, 0x03):
                return XpressNetCommandResult(code, Status.OK, data[1:])
            else:
                raise XpressNetException(f"Unknown interface status response 0x{subcode:02X}")
        elif code == Command.ACCESSORY_REPORT:
            return AccessoryStateMessage(data)
            # logging.warning(f"Don't know how to handle {str(code)} 0x{self.__hex(data)}")
        else:
            raise XpressNetException(f"Unknown response code 0x{code:02X}")

    def __handle_response(self, cmd):
        while True:
            bytes = self.__read(3)
            try:
                (preamble, header) = struct.unpack("!HB", bytes)
            except struct.error:
                logging.warning(f"Unable to process data 0x{self.__hex(bytes)}")
                continue
            code = Command(header & 0xF0)
            length = header & 0x0F  # the length, without the command code
            try:
                data = self.__recv_checksummed_data(header, length)
            except XpressNetException as e:
                logging.warning(f"Unable to process message {code}({length}): {e.args}")
                continue
            if preamble == 0xFFFE:
                return self.__get_status(cmd, False, code, length, data)
            if preamble == 0xFFFD:
                # broadcast message: page 13, chapter 3
                s = self.__get_status(cmd, True, code, length, data)
                if type(s) == TrackStatusMessage:
                    self.track_status = s.state
                logging.debug(f"broadcast: {self.last_broadcast}")
                self.last_broadcast = s
                return s
                # continue
            raise XpressNetException(f"Unknown response data 0x{preamble:04X}")

    def __recv_checksummed_data(self, previous, length):
        """
        Receive the desired amount of data bytes. Raises exception if the checksum is not correct.
        :param previous: previous bytearray data to include in checksum calculation
        :param length: data bytes (excluding checksum byte)
        :return: bytearray of received data
        """
        length = length + 1
        data = self.__read(length)
        if len(data) != length:
            raise XpressNetException(f"Expected {length} bytes, got {len(data)}")
        if type(previous) == int:
            previous = bytearray([previous])
        self.__checksum(previous + data[0:-1], data[-1])
        return data[0:-1]

    def __checksum(self, data, sum):
        if reduce(lambda r, v: r ^ v, data) != sum:
            raise XpressNetException(f"Checksum error: 0x{sum:02X} for 0x{self.__hex(data)}")

    def __hex(self, data):
        return ''.join(f'{c:02X}' for c in data)

    def __bcd(self, data):
        return f"{data >> 4}.{data & 0x0F}"

    def cmd(self, cmd, params=None, expected=None):
        cmd = Command(cmd & 0xF0)
        params = params if params else bytearray()
        if expected is None:
            expected = cmd

        self.send(bytearray([cmd | len(params)]) + bytearray(params))
        data = self.__handle_response(cmd)
        logging.debug(f"{str(cmd)}({self.__hex(params)}): {str(data.status)} = {self.__hex(data.data)}")

        if data.code == 0:
            # non-immediate response, data contains specifics
            return data
        if data.code != expected:
            raise XpressNetException(f"Response code 0x{data.code:02X} != 0x{expected:02X}")
        return data

    def receive_one(self):
        self.__handle_response(None)

    def get_xpressnet_interface_version(self):
        """
        The version of XpressNet supported by the interface
        page 9, section 1.6
        :return: string from the BCD encoded version number
        """
        r = self.cmd(Command.INTERFACE, expected=0x00)
        if len(r.data) != 2:
            raise XpressNetException("Invalid response")
        return f"{self.__bcd(r.data[0])}, {self.__bcd(r.data[1])}"

    def get_xpressnet_interface_status(self):
        """
        Is the interface communicating with the command station?
        page 11, section 2.1
        :return:
        """
        r = self.cmd(Command.INTERFACE, [0x01])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return r.data[0] & 0x01 == 1

    def get_xpressnet_version(self):
        """
        The version of XpressNet supported by the interface.
        page 11, section 2.1
        :return: string from the BCD encoded version number
        """
        r = self.cmd(Command.INTERFACE, [0x02])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return self.__bcd(r.data[0])

    def get_xpressnet_available_connections(self):
        """
        The number of concurrent network connections that can be made to this interface.
        page 11, section 2.1
        :return: string from the BCD encoded version number
        """
        r = self.cmd(Command.INTERFACE, [0x03])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return r.data[0]

    def get_xpressnet_interface_address(self):
        """
        The number of concurrent network connections that can be made to this interface.
        page 10, section 1.7
        :return: address as integer
        """
        r = self.cmd(Command.INTERFACE, [0x01, 0])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return r.data[0]

    def get_last_broadcast(self):
        return self.last_broadcast

    def set_all_off(self):
        """
        Turn off power to the tracks.
        :return:
        """
        self.cmd(Command.PROGRAMMING, [0x80])

    def set_all_on(self):
        """
        Turn power on to the tracks.
        :return:
        """
        self.cmd(Command.PROGRAMMING, [0x81])


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    x = XpressNet(sys.argv[1], 5550)

    x.open()

    logging.info(f"Interface version: {x.get_xpressnet_interface_version()}")
    logging.info(f"Interface address: {x.get_xpressnet_interface_address()}")
    logging.info(f"Interface is connected to Command Station: {x.get_xpressnet_interface_status()}")
    logging.info(f"Interface supports XpressNet version: {x.get_xpressnet_version()}")
    logging.info(f"Interface available connections: {x.get_xpressnet_available_connections()}")

    x.set_all_off()
    # x.set_all_on()

    while True:
        x.receive_one()
        # print(f"Status: {x.get_last_broadcast()}")

    x.close()
