#!/usr/bin/env python

import logging

from functools import reduce
from socket import socket, timeout, AF_INET, SOCK_STREAM
from struct import unpack


class XpressNetException(Exception):
    pass


class XpressNetCommandException(XpressNetException):
    msg = [
        "no error",
        "wrong number of bytes in command",
        "timeout",
        "unknown",
        "sent to command station",
        "ping",
        "buffer overflow",
        "unable to receive",
        "invalid parameter",
        "unknown"
    ]

    def __init__(self, error):
        self.errorCode = error
        if error < len(self.msg):
            super().__init__(self, self.msg[error])
        else:
            super().__init__(self, f"unknown {error}")


class XpressNetProgrammingException(XpressNetException):
    msg = {
        0x11: "ready",
        0x12: "short circuit",
        0x13: "not found",
        0x1f: "busy"
    }

    def __init__(self, error):
        self.errorCode = error
        if error in self.msg:
            super(self.msg[error])
        else:
            super(f"unknown {error}")


class XpressNetCommandResult:
    def __init__(self, code, data):
        self.code = code
        self.data = data

    def __repr__(self):
        return f"0x{self.code:02X}({self.data})"

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

    def open(self):
        logging.debug("Opening connection")
        self.sock.connect((self.host, self.port))
        self.sock.settimeout(1.0)
        try:
            self.sock.recv(512) # flush any remaining unread data
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
        logging.debug(f"Sending {len(buffer)}: {self.__hex(buffer)}")
        self.sock.send(buffer)

    def __read(self, length):
        data = self.sock.recv(length)
        logging.debug(f"Received {len(data)}: {self.__hex(data)}")
        return data

    def __handle_response(self):
        while True:
            (preamble, header) = unpack("!HB", self.__read(3))
            code = header & 0xF0 # the command code, without the length
            length = header & 0x0F # the length, without the command code
            data = self.__recv_checksummed_data(header, length)
            if preamble == 0xFFFE:
                # response is a regular message
                if code == 0x00:
                    # communication error: page 7, section 1.5
                    # interface version number: page 9, section 1.6
                    return XpressNetCommandResult(code, data)
                    # raise XpressNetCommandException(error[0])
                # elif code == 0x61:
                #     # programming mode response: page 16, section 3.1.2
                #     error = self.__recv_checksummed_data(code, 1)
                #     raise XpressNetProgrammingException(error[0])
                elif code == 0x60:
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
                        return XpressNetProgrammingResult(cv+256, value)
                    elif subcode == 0x16:
                        # programming mode response data 4 bytes, CV 512-767: page 19, section 3.1.2.8
                        return XpressNetProgrammingResult(cv+512, value)
                    elif subcode == 0x17:
                        # programming mode response data 4 bytes, CV 768-1023: page 20, section 3.1.2.9
                        return XpressNetProgrammingResult(cv+768, value)
                    else:
                        raise XpressNetException(f"Unknown programming response code {code[0]:X}/{subcode[0]:X}")
                elif code == 0xF0:
                    (subcode,) = data[0:1]
                    if subcode in (0x01, 0x02, 0x03):
                        return XpressNetCommandResult(code, data[1:])
                    else:
                        raise XpressNetException(f"Unknown interface status response 0x{subcode:02X}")
                else:
                    raise XpressNetException(f"Unknown response code 0x{code[0]:02X}")
            if preamble == 0xFFFD:
                # broadcast message: page 13, chapter 3
                self.last_broadcast = XpressNetCommandResult(code, data)
                return self.last_broadcast
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
            raise XpressNetException("Expected {len} bytes, got {len(data)}")
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
        cmd = cmd & 0xF0
        if params:
            self.send(bytearray([cmd | len(params)]) + bytearray(params))
        else:
            self.send(bytearray([cmd]))
        if expected is None:
            expected = cmd
        data = self.__handle_response()
        if data.code == 0:
            # non-immediate response, data contains specifics
            return data
        if data.code != expected:
            raise XpressNetException(f"Response code 0x{data.code:02X} != 0x{expected:02X}")
        return data

    def receive_one(self):
        self.__handle_response()

    def get_xpressnet_interface_version(self):
        """
        The version of XpressNet supported by the interface
        page 9, section 1.6
        :return: string from the BCD encoded version number
        """
        r = self.cmd(0xF0, expected=0x00)
        if len(r.data) != 2:
            raise XpressNetException("Invalid response")
        return f"{self.__bcd(r.data[0])}, {self.__bcd(r.data[1])}"

    def get_xpressnet_interface_status(self):
        """
        Is the interface communicating with the command station?
        page 11, section 2.1
        :return:
        """
        r = self.cmd(0xF0, [0x01])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return r.data[0] & 0x01 == 1

    def get_xpressnet_version(self):
        """
        The version of XpressNet supported by the interface.
        page 11, section 2.1
        :return: string from the BCD encoded version number
        """
        r = self.cmd(0xF0, [0x02])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return self.__bcd(r.data[0])

    def get_xpressnet_available_connections(self):
        """
        The number of concurrent network connections that can be made to this interface.
        page 11, section 2.1
        :return: string from the BCD encoded version number
        """
        r = self.cmd(0xF0, [0x03])
        if len(r.data) != 1:
            raise XpressNetException("Invalid response")
        return r.data[0]

    def get_xpressnet_interface_address(self):
        """
        The number of concurrent network connections that can be made to this interface.
        page 10, section 1.7
        :return: address as integer
        """
        r = self.cmd(0xF0, [0x01, 0])
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
        self.cmd(0x21, [0x80])

    def set_all_on(self):
        """
        Turn power on to the tracks.
        :return:
        """
        self.cmd(0x21, [0x81])


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    x = XpressNet("192.168.1.200", 5550)

    x.open()

    # print(f"Interface version: {x.get_xpressnet_interface_version()}")
    # print(f"Interface address: {x.get_xpressnet_interface_address()}")
    # print(f"Interface is connected to Command Station: {x.get_xpressnet_interface_status()}")
    # print(f"Interface supports XpressNet version: {x.get_xpressnet_version()}")
    # print(f"Interface available connections: {x.get_xpressnet_available_connections()}")
    #
    # x.set_all_on()

    while True:
        x.receive_one()
        print(f"Status: {x.get_last_broadcast()}")


    x.close()
