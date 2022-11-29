import logging
import math
import re
import socket
import struct

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def ip2int(addr):
    # convert decimal dotted quad string to long integer"
    # @ is native, ! is big-endian, native didnt work" \
    # returned the octects reversed main.integerToDecimalDottedQuad(main.decimalDottedQuadToInteger('149.246.14.224'))"
    ip_as_int = struct.unpack('!i', socket.inet_aton(addr))[0]
    if ip_as_int < 0:
        ip_as_int = ip_as_int + 2 ** 32
    return ip_as_int

def int2ip(addr):
    return (str((0xff000000 & addr) >> 24) + '.' +
            str((0x00ff0000 & addr) >> 16) + '.' +
            str((0x0000ff00 & addr) >> 8) + '.' +
            str((0x000000ff & addr)))

def cidr_to_netmask(cidr):
  cidr = int(cidr)
  mask = (0xffffffff >> (32 - cidr)) << (32 - cidr) # wenn cidr=24, 32-cidr = 8
  #0xffffffff >> 8 = int("0000 0000 1111 1111 1111 1111 1111 1111")
  #0xffffff << 8 ->  int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = int("1111 1111 1111 1111 1111 1111 0000 0000")
  #int("0000 0000 1111 1111 1111 1111 1111 1111") << 8 = ˜int("0000 0000 1111 1111 1111 1111 1111 1111")=int("1111 1111 1111 1111 1111 1111 0000 0000")
  #~x
  #Returns the complement of x - the number you get by switching each 1 for a 0 and each 0 for a 1
  return int2ip(mask)

def netmask_to_cidr(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0)
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def makeIntegerMask(cidr):
    #return a mask of n bits as a long integer
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return mask

def correctAndCheckMatchedMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    mask = resultMask.group(1)
    mask = int(mask)
    if mask >= 0 and mask <= 32:
        return mask
    else:
        raise BaseException("Mask is less,equal to -1, mask is bigger,equal to 33")


def isMask(cidr):
    patternMask = re.compile('[^\d]*(\d+)[^\d]*$')
    resultMask = patternMask.match(cidr)
    if resultMask:
        return True
    else:
        return False

def isIntegerAddressInIntegerNetwork(ip,net):
   #Is an address in a network"
   return ip & net == net

def isPrefix(ipaddr):
    patternPrefix = re.compile('.*?([0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}[^\d]+[0-9]{1,3}).*$')
    resultPrefix = patternPrefix.match(ipaddr)
    #first digit that it starts with is [1-9]
    patternPrefixCommaSeparated = re.compile('[^\d]*?([1-9][0-9]{10,11}).*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)
    if resultPrefix or resultPrefixCommaSeparated:
        return True
    else:
        return False

def correctMatchedPrefix(ipaddr):

    patternPrefixCommaSeparated = re.compile('^\s*([1-9][0-9]{10,11})\s*$')
    resultPrefixCommaSeparated = patternPrefixCommaSeparated.match(ipaddr)

    if resultPrefixCommaSeparated:
        digits = [int(x) for x in str(resultPrefixCommaSeparated.group(1))]
        l=len(digits)
        fourthoctet  = [digits[l-3]*100, digits[l-2]*10, digits[l-1]]
        thirdoctet = [digits[l-x]*math.pow(10, x-4)  for x in range(6, 3, -1)]
        secondoctet  = [digits[l-x]*math.pow(10, x-7) for x in range(9, 6, -1)]
        firstoctet = [digits[l-x]*math.pow(10, x-10) for x in range(l, 9, -1)]
        ip = ".".join([str(int(sum(firstoctet))),str(int(sum(secondoctet))),str(int(sum(thirdoctet))),str(int(sum(fourthoctet)))])
        return ip

def ip_range_explode(ip,netmask):

        prefix2 = ip
        cidr2 = netmask_to_cidr(netmask)

        base = int2ip(
            ip2int(prefix2) & makeIntegerMask(
                cidr2))
        if base != prefix2:
            logging.getLogger("ip_utils").log(level=logging.ERROR,
                                      msg="%s Not a network address (possible ip base %s)" % (ip,base))

        int_prefix_top = (~makeIntegerMask(
            cidr2)) | ip2int(prefix2)
        prefix_top = int2ip(int_prefix_top)

        list_unpacked_ips=[]
        for j in range(ip2int(base) + 1,
                       ip2int(
                           int2ip(int_prefix_top)) + 1):
            list_unpacked_ips.append(int2ip(j))
        return list_unpacked_ips

def iprange_to_cidr(inet_start, inet_stop):
    # convert the first ip of the range to an integer
    start = ip2int(inet_start)
    # convert the last ip of the range to an integer
    stop = ip2int(inet_stop)
    # calculate the difference between the two integers
    # the number of bits needed to represent the difference subtracted from 32 is the cidr
    diff = stop - start
    # calculate the number of bits needed to represent the difference
    bits = math.ceil(math.log(diff, 2))
    # calculate the cidr
    cidr = 32 - bits
    return cidr

def is_network_address(prefix2,cidr2):
    base = int2ip(ip2int(prefix2) & makeIntegerMask(cidr2))
    res= (base == prefix2)
    if not res:
        logging.getLogger("ip_utils").log(level=logging.ERROR,
                                      msg="%s Not a network address (possible ip base %s)" %(prefix2,base))
    return res

def is_prefix_top(start,end,cidr2):
    mask = makeIntegerMask(cidr2)
    mask = ~mask
    if mask < 0:
        mask = mask + 2 ** 32

    int_prefix_top = mask | ip2int(start)
    prefix_top = int2ip(int_prefix_top)
    res = (prefix_top == end)
    if not res:
        logging.getLogger("ip_utils").log(level=logging.ERROR,
                                      msg="%s Not a prefix top (possible ip top %s)" % (end,prefix_top))
    return res


def base_cidr_to_range(prefix2, cidr2):
    is_network_address(prefix2,cidr2)
    mask=makeIntegerMask(cidr2)
    mask=~mask
    if mask < 0:
        mask = mask + 2 ** 32

    int_prefix_top = mask | ip2int(prefix2)
    prefix_top = int2ip(int_prefix_top)
    return prefix2, prefix_top