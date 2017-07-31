
'''
Author: Chris Eagle
Name: Clemency processor for defcon 25
How: Install into <idadir>/procs
     Choose this from the processors drop down when loading a clemency 9-bit middle-endian binary
'''
   
import string
import sys
import idaapi
from idaapi import *
import idc
from idc import *
import struct
import re
from functools import partial

_pc = 0

def get_start(ea):
   while True:
      b = Byte(ea)
      if b < 0x100 and chr(b) in string.printable:
         ea -= 1
      else:
         return ea + 1

def make_str(ea):
   res = ''
   while True:
      b = Byte(ea)
      if b < 0x100 and chr(b) in string.printable:
         res += chr(b)
         ea += 1
      else:
         return res

"""
Celemency assembler supporting labels.

A sample program computing 1+2+...+100:

    ldt r1, [r0 + data, 1]
next:
    adi r2, r2, 1
    ad r3, r3, r2
    cm r2, r1
    bl next
    ht
data:
    .dt 100
"""

_pc = 0

def _encode_num(n, size):
    x = bin(int(n, 0) & ((1 << size) - 1))[2:].zfill(size)
    return x

def _encode_reg_count(n, size):
    return _encode_num(str(int(n, 0) - 1), size)

def _encode_location(label_or_location):
    try:
        x = int(label_or_location, 0)
    except:
        x = LocByName(label_or_location)
    return _encode_num("%d" % x, 27)

def _encode_offset(label_or_offset, size=27):
    try:
        x = int(label_or_offset, 0)
    except:
        x = LocByName(label_or_offset) - _pc
    return _encode_num("%d" % x, size)

def _encode_reg(reg):
    x = bin(int(reg.lower().replace('st', 'r29').replace('sp', 'r29').replace('ra', 'r30').replace('pc', 'r31').replace('r', '')))[2:].zfill(5)
    if len(x) > 5:
        raise ValueError("encoded number too large")
    return x

def encode_me(bits):
    if len(bits) == 0:
        return ''
    elif len(bits) == 18:
        return bits[9:18] + bits[0:9]
    elif len(bits) == 27:
        return bits[9:18] + bits[0:9] + bits[18:27]
    elif len(bits) == 36:
        return bits[9:18] + bits[0:9] + bits[18:27] + bits[27:36]
    elif len(bits) == 54:
        return bits[9:18] + bits[0:9] + bits[18:27] + bits[36:45] + bits[27:36] + bits[45:54]
    else:
        raise ValueError('unsupported bit length')

#
# ADD HANDLERS BELOW HERE
#

# A

def assemble_ad(rA, rB, rC, *args):
    "Yan"
    return "0000000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_adc(rA, rB, rC, *args):
    "Yan"
    return "0100000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_adci(rA, rB, imm, *args):
    "Yan"
    return "0100000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

def assemble_adcim(rA, rB, imm, *args):
    "Yan"
    return "0100010" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

def assemble_adcm(rA, rB, rC, *args):
    "Yan"
    return "0100010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_adf(rA, rB, rC, *args):
    "Yan"
    return "0000001" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_adfm(rA, rB, rC, *args):
    "Yan"
    return "0000011" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_adi(rA, rB, imm, *args):
    "Yan"
    return "0000000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

def assemble_adim(rA, rB, imm, *args):
    "Yan"
    return "0000010" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

def assemble_adm(rA, rB, rC, *args):
    "Yan"
    return "0000010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_an(rA, rB, rC, *args):
    "Yan"
    return "0010100" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_ani(rA, rB, imm, *args):
    "Yan"
    return "0010100" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

def assemble_anm(rA, rB, rC, *args):
    "Yan"
    return "0010110" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")
# B

def assemble_b(offset):
    return "110000" + "1111" + _encode_offset(offset, 17)

def assemble_bn(offset):
    return "110000" + "0000" + _encode_offset(offset, 17)

def assemble_be(offset):
    return "110000" + "0001" + _encode_offset(offset, 17)

def assemble_bl(offset):
    return "110000" + "0010" + _encode_offset(offset, 17)

def assemble_ble(offset):
    return "110000" + "0011" + _encode_offset(offset, 17)

def assemble_bg(offset):
    return "110000" + "0100" + _encode_offset(offset, 17)

def assemble_bge(offset):
    return "110000" + "0101" + _encode_offset(offset, 17)

def assemble_bno(offset):
    return "110000" + "0110" + _encode_offset(offset, 17)

def assemble_bo(offset):
    return "110000" + "0111" + _encode_offset(offset, 17)

def assemble_bns(offset):
    return "110000" + "1000" + _encode_offset(offset, 17)

def assemble_bs(offset):
    return "110000" + "1001" + _encode_offset(offset, 17)

def assemble_bsl(offset):
    return "110000" + "1010" + _encode_offset(offset, 17)

def assemble_bsle(offset):
    return "110000" + "1011" + _encode_offset(offset, 17)

def assemble_bsg(offset):
    return "110000" + "1100" + _encode_offset(offset, 17)

def assemble_bsge(offset):
    return "110000" + "1101" + _encode_offset(offset, 17)

def assemble_bf(rA, rB, *args):
    return "101001100" + _encode_reg(rA) + _encode_reg(rB) + "1000000" + ("1" if len(args) else "0")

def assemble_bfm(rA, rB, *args):
    return "101001100" + _encode_reg(rA) + _encode_reg(rB) + "1000000" + ("1" if len(args) else "0")

def assemble_br(rA):
    return "110000" + "1111" + _encode_reg(rA) + "000"

def assemble_brn(rA):
    return "110000" + "0000" + _encode_reg(rA) + "000"

def assemble_bre(rA):
    return "110000" + "0001" + _encode_reg(rA) + "000"

def assemble_brl(rA):
    return "110000" + "0010" + _encode_reg(rA) + "000"

def assemble_brle(rA):
    return "110000" + "0011" + _encode_reg(rA) + "000"

def assemble_brg(rA):
    return "110000" + "0100" + _encode_reg(rA) + "000"

def assemble_brge(rA):
    return "110000" + "0101" + _encode_reg(rA) + "000"

def assemble_brno(rA):
    return "110000" + "0110" + _encode_reg(rA) + "000"

def assemble_bro(rA):
    return "110000" + "0111" + _encode_reg(rA) + "000"

def assemble_brns(rA):
    return "110000" + "1000" + _encode_reg(rA) + "000"

def assemble_brs(rA):
    return "110000" + "1001" + _encode_reg(rA) + "000"

def assemble_brsl(rA):
    return "110000" + "1010" + _encode_reg(rA) + "000"

def assemble_brsle(rA):
    return "110000" + "1011" + _encode_reg(rA) + "000"

def assemble_brsg(rA):
    return "110000" + "1100" + _encode_reg(rA) + "000"

def assemble_brsge(rA):
    return "110000" + "1101" + _encode_reg(rA) + "000"

def assemble_bra(location):
    return "111000100" + _encode_location(location)

def assemble_brr(offset):
    return "111000000" + _encode_offset(offset)
# C

# zanardi
# C: Call Conditional
def assemble_cn(offset, *args):
    return "110101" + "0000" + _encode_offset(offset, 17)

def assemble_ce(offset, *args):
    return "110101" + "0001" + _encode_offset(offset, 17)

def assemble_cl(offset, *args):
    return "110101" + "0010" + _encode_offset(offset, 17)

def assemble_cle(offset, *args):
    return "110101" + "0011" + _encode_offset(offset, 17)

def assemble_cg(offset, *args):
    return "110101" + "0100" + _encode_offset(offset, 17)

def assemble_cge(offset, *args):
    return "110101" + "0101" + _encode_offset(offset, 17)

def assemble_cno(offset, *args):
    return "110101" + "0110" + _encode_offset(offset, 17)

def assemble_co(offset, *args):
    return "110101" + "0111" + _encode_offset(offset, 17)

def assemble_cns(offset, *args):
    return "110101" + "1000" + _encode_offset(offset, 17)

def assemble_cs(offset, *args):
    return "110101" + "1001" + _encode_offset(offset, 17)

def assemble_csl(offset, *args):
    return "110101" + "1010" + _encode_offset(offset, 17)

def assemble_csle(offset, *args):
    return "110101" + "1011" + _encode_offset(offset, 17)

def assemble_csg(offset, *args):
    return "110101" + "1100" + _encode_offset(offset, 17)

def assemble_csge(offset, *args):
    return "110101" + "1101" + _encode_offset(offset, 17)

def assemble_c(offset, *args):
    return "110101" + "1111" + _encode_offset(offset, 17)

# CAA: Call Absolute
def assemble_caa(location, *args):
    return "111001100" + _encode_location(location)

# CAR: Call Relative
def assemble_car(offset, *args):
    return "111001000" + _encode_offset(offset)

# CM: Compare
def assemble_cm(rA, rB, *args):
    return "10111000" + _encode_reg(rA) + _encode_reg(rB)

# CMF: Compare Floating Point
def assemble_cmf(rA, rB, *args):
    return "10111010" + _encode_reg(rA) + _encode_reg(rB)

# CMFM: Compare Floating Point Multi Reg
def assemble_cmfm(rA, rB, *args):
	return "10111110" + _encode_reg(rA) + _encode_reg(rB)

# CMI: Compare Immediate
def assemble_cmi(rA, imm, *args):
	return "10111001" + _encode_reg(rA) + _encode_num(imm, 14)

# CMIM: Compare Immediate Multi Reg
def assemble_cmim(rA, imm, *args):
	return "10111101" + _encode_reg(rA) + _encode_num(imm, 14)

# CMM: Compare Multi Reg
def assemble_cmm(rA, rB, *args):
	return "10111100" + _encode_reg(rA) + _encode_reg(rB)

# CR: Call Register Conditional
def assemble_crn(rA, *args):
    return "110101" + "0000" + _encode_reg(rA) + "000"

def assemble_cre(rA, *args):
    return "110101" + "0001" + _encode_reg(rA) + "000"

def assemble_crl(rA, *args):
    return "110101" + "0010" + _encode_reg(rA) + "000"

def assemble_crle(rA, *args):
    return "110101" + "0011" + _encode_reg(rA) + "000"

def assemble_crg(rA, *args):
    return "110101" + "0100" + _encode_reg(rA) + "000"

def assemble_crge(rA, *args):
    return "110101" + "0101" + _encode_reg(rA) + "000"

def assemble_crno(rA, *args):
    return "110101" + "0110" + _encode_reg(rA) + "000"

def assemble_cro(rA, *args):
    return "110101" + "0111" + _encode_reg(rA) + "000"

def assemble_crns(rA, *args):
    return "110101" + "1000" + _encode_reg(rA) + "000"

def assemble_crs(rA, *args):
    return "110101" + "1001" + _encode_reg(rA) + "000"

def assemble_crsl(rA, *args):
    return "110101" + "1010" + _encode_reg(rA) + "000"

def assemble_crsle(rA, *args):
    return "110101" + "1011" + _encode_reg(rA) + "000"

def assemble_crsg(rA, *args):
    return "110101" + "1100" + _encode_reg(rA) + "000"

def assemble_crsge(rA, *args):
    return "110101" + "1101" + _encode_reg(rA) + "000"

def assemble_cr(rA, *args):
    return "110101" + "1111" + _encode_reg(rA) + "000"


# D
def assemble_dbrk():
    return "111111111111111111"

def assemble_di(rA):
    return "101000000101{}0".format(_encode_reg(rA))

def assemble_dmt(rA, rB, rC):
    return "0110100{}{}{}00000".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC))

def assemble_dv(rA, rB, rC, *args):
    return "0001100{}{}{}0000{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

def assemble_dvf(rA, rB, rC, *args):
    return "0001101{}{}{}0000{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

def assemble_dvmf(rA, rB, rC, *args):
    return "0001111{}{}{}0000{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

def assemble_dvi(rA, rB, imm, *args):
    return "0001100{}{}{}01{}".format(_encode_reg(rA), _encode_reg(rB), _encode_num(imm, 7), ("1" if len(args) else "0"))

def assemble_dvim(rA, rB, imm, *args):
    return "0001110{}{}{}01{}".format(_encode_reg(rA), _encode_reg(rB), _encode_num(imm, 7), ("1" if len(args) else "0"))

def assemble_dvis(rA, rB, imm, *args):
    return "0001100{}{}{}11{}".format(_encode_reg(rA), _encode_reg(rB), _encode_num(imm, 7), ("1" if len(args) else "0"))

def assemble_dvism(rA, rB, imm, *args):
    return "0001110{}{}{}11{}".format(_encode_reg(rA), _encode_reg(rB), _encode_num(imm, 7), ("1" if len(args) else "0"))

def assemble_dvm(rA, rB, rC, *args):
    return "0001110{}{}{}0000{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

def assemble_dvs(rA, rB, rC, *args):
    return "0001100{}{}{}0010{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

def assemble_dvsm(rA, rB, rC, *args):
    return "0001110{}{}{}0010{}".format(_encode_reg(rA), _encode_reg(rB), _encode_reg(rC), ("1" if len(args) else "0"))

# E

# EI: Enable Interrupts
def assemble_ei(rA, *args):
    """EDG"""
    return "101000000100" + _encode_reg(rA) + "0"

# F
def assemble_fti(rA, rB):
    return "101000101{}{}00000000".format(_encode_reg(rA), _encode_reg(rB))

def assemble_ftim(rA, rB):
    return "101000111{}{}00000000".format(_encode_reg(rA), _encode_reg(rB))
# H

def assemble_ht():
    return "101000000011000000"

# I
def assemble_ir():
    return "101000000001000000"

def assemble_itf(rA, rB):
    return "101000100{}{}00000000".format(_encode_reg(rA), _encode_reg(rB))

def assemble_itfm(rA, rB):
    return "101000110{}{}00000000".format(_encode_reg(rA), _encode_reg(rB))

# J

# K - there is no k

# L
# cub01d
def assemble_lds(rA, rB, offset, _regcount, mode="0"):
    return "1010100" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(_regcount, 5) + \
             _encode_num(mode, 2) + _encode_offset(offset) + "000"
def assemble_ldsi(rA, rB, offset, _regcount):
    return assemble_lds(rA, rB, offset, _regcount, mode="1")
def assemble_ldsd(rA, rB, offset, _regcount):
    return assemble_lds(rA, rB, offset, _regcount, mode="2")

# iceboy
def assemble_ldt(rA, rB, offset, reg_count, mode="0"):
    return "1010110" + _encode_reg(rA) + _encode_reg(rB) + \
           _encode_reg_count(reg_count, 5) + _encode_num(mode, 2) + \
           _encode_offset(offset) + "000"

assemble_ldti = partial(assemble_ldt, mode="1")
assemble_ldtd = partial(assemble_ldt, mode="2")

# iceboy
def assemble_ldw(rA, rB, offset, reg_count, mode="0"):
    return "1010101" + _encode_reg(rA) + _encode_reg(rB) + \
           _encode_reg_count(reg_count, 5) + _encode_num(mode, 2) + \
           _encode_offset(offset) + "000"

assemble_ldwi = partial(assemble_ldw, mode="1")
assemble_ldwd = partial(assemble_ldw, mode="2")

# M

# MD: Modulus
def assemble_md(rA, rB, rC,  *args):
    return "0010000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

# MDF: Modulus Floating Point
def assemble_mdf(rA, rB, rC,  *args):
    return "0010001" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

# MDFM: Modulus Floating Point Multi Reg
def assemble_mdf(rA, rB, rC,  *args):
    return "0010011" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

# MDI: Modulus Immediate
def assemble_mdi(rA, rB, imm,  *args):
    return "0010000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

# MDIM: Modulus Immediate Multi Reg
def assemble_mdim(rA, rB, imm,  *args):
    return "0010010" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")

# MDIS: Modulus Immediate Signed
def assemble_mdis(rA, rB, imm,  *args):
    return "0010000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "11" + ("1" if len(args) else "0")

# MDISM: Modulus Immediate Signed Multi Reg
def assemble_mdism(rA, rB, imm,  *args):
    return "0010010" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "11" + ("1" if len(args) else "0")

# MDM: Modulus Multi Reg
def assemble_mdm(rA, rB, rC,  *args):
    return "0010010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

# MDS: Modulus Signed
def assemble_mds(rA, rB, rC,  *args):
    return "0010000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0010" + ("1" if len(args) else "0")

# MDSM: Modulus Signed Multi Reg
def assemble_mdsm(rA, rB, rC,  *args):
    return "0010010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0010" + ("1" if len(args) else "0")


def assemble_mh(rA, imm, *args):
    return '10001' + _encode_reg(rA) + _encode_num(imm, 17)

def assemble_ml(rA, imm, *args):
    return '10010' + _encode_reg(rA) + _encode_num(imm, 17)

def assemble_mi(rA, imm, *args):
    imm = _encode_num(imm, 27).zfill(27)
    #print "IMMEDIATE: %d %s", imm
    #print '0b'+imm[-9:]
    #print '0b'+imm[:-9]
    return assemble_ml(rA, '0b'+imm[-10:]) + assemble_mh(rA, '0b'+imm[:-10])

def assemble_ms(rA, imm, *args):
    return '10011' + _encode_reg(rA) + _encode_num(imm, 17)

def assemble_mu(rA, rB, rC, *args):
    return '0001000' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ("1" if len(args) else "0")

def assemble_muf(rA, rB, rC, *args):
    return '0001001' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ("1" if len(args) else "0")

def assemble_mufm(rA, rB, rC, *args):
    return '0001011' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ("1" if len(args) else "0")

def assemble_mui(rA, rB, imm, *args):
    return '0001000' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ("1" if len(args) else "0")

def assemble_muim(rA, rB, imm, *args):
    return '0001010' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ("1" if len(args) else "0")

def assemble_muis(rA, rB, imm, *args):
    return '0001000' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '11' + ("1" if len(args) else "0")

def assemble_muism(rA, rB, imm, *args):
    return '0001010' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '11' + ("1" if len(args) else "0")

def assemble_mum(rA, rB, rC, *args):
    return '0001010' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ("1" if len(args) else "0")

def assemble_mus(rA, rB, rC, *args):
    return '0001000' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0010' + ("1" if len(args) else "0")

def assemble_musm(rA, rB, rC, *args):
    return '0001010' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0010' + ("1" if len(args) else "0")

# N

# jmgrosen
def assemble_ng(rA, rB, *args):
    return "101001100" + _encode_reg(rA) + _encode_reg(rB) + "0000000" + ("1" if len(args) else "0")

# jmgrosen
def assemble_ngf(rA, rB, *args):
    return "101001101" + _encode_reg(rA) + _encode_reg(rB) + "0000000" + ("1" if len(args) else "0")

# jmgrosen
def assemble_ngfm(rA, rB, *args):
    return "101001111" + _encode_reg(rA) + _encode_reg(rB) + "0000000" + ("1" if len(args) else "0")

# jmgrosen
def assemble_ngm(rA, rB, *args):
    return "101001110" + _encode_reg(rA) + _encode_reg(rB) + "0000000" + ("1" if len(args) else "0")

# jmgrosen
def assemble_nt(rA, rB, *args):
    return "101001100" + _encode_reg(rA) + _encode_reg(rB) + "0100000" + ("1" if len(args) else "0")

# jmgrosen
def assemble_ntm(rA, rB, *args):
    return "101001110" + _encode_reg(rA) + _encode_reg(rB) + "0100000" + ("1" if len(args) else "0")


# O


def assemble_or(rA, rB, rC, *args):
    "Fish"
    return "0011000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")


def assemble_ori(rA, rB, imm, *args):
    "Fish"
    return "0011000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")


def assemble_orm(rA, rB, rC, *args):
    "Fish"
    return "0011010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")


# P - there is no p

# Q - there is no q

# R

def assemble_re():
    return "101000000000000000"

def assemble_rf(rA):
    return "101000001100" + _encode_reg(rA) + "0"

def assemble_rl(rA, rB, rC, *args):
    return "0110000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_rli(rA, rB, imm, *args):
    return "1000000" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "00" + ("1" if len(args) else "0")

def assemble_rlim(rA, rB, imm, *args):
    return "1000010" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "00" + ("1" if len(args) else "0")

def assemble_rlm(rA, rB, rC, *args):
    return "0110010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_rmp(rA, rB):
    return "1010010" + _encode_reg(rA) + _encode_reg(rB) + "0000000000"

def assemble_rnd(rA, *args):
    return "101001100" + _encode_reg(rA) + "000001100000" + ("1" if len(args) else "0")

def assemble_rri(rA, rB, imm, *args):
    return "1000001" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "00" + ("1" if len(args) else "0")

def assemble_rrim(rA, rB, imm, *args):
    return "1000011" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "00" + ("1" if len(args) else "0")

def assemble_rrm(rA, rB, rC, *args):
    return "0110011" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")
# S


def assemble_sa(rA, rB, rC, *args):
    return '0101101' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sai(rA, rB, imm, *args):
    return '0111101' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')

def assemble_saim(rA, rB, imm, *args):
    return '0111111' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')

def assemble_sam(rA, rB, rC, *args):
    return '0101111' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sb(rA, rB, rC, *args):
    return '0000100' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sbc(rA, rB, rC, *args):
    return '0100100' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sbci(rA, rB, imm, *args):
    return '0100100' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ('1' if len(args) else '0')

def assemble_sbcim(rA, rB, imm, *args):
    return '0100110' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ('1' if len(args) else '0')

def assemble_sbcm(rA, rB, rC, *args):
    return '0100110' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sbf(rA, rB, rC, *args):
    return '0000101' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sbfm(rA, rB, rC, *args):
    return '0000111' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sbi(rA, rB, imm, *args):
    return '0000100' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ('1' if len(args) else '0')

def assemble_sbim(rA, rB, imm, *args):
    return '0000110' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '01' + ('1' if len(args) else '0')

def assemble_sbm(rA, rB, rC, *args):
    return '0000110' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_ses(rA, rB, *args):
    return '101000000111' + _encode_reg(rA) + _encode_reg(rB) + '00000'

def assemble_sew(rA, rB, *args):
    return '101000001000' + _encode_reg(rA) + _encode_reg(rB) + '00000'

def assemble_sf(rA, *args):
    return '101000001011' + _encode_reg(rA) + '0'

def assemble_sl(rA, rB, rC, *args):
    return '0101000' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sli(rA, rB, imm, *args):
    return '0111000' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')

def assemble_slim(rA, rB, imm, *args):
    return '0111010' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')

def assemble_slm(rA, rB, rC, *args):
    return '0101010' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_smp(rA, rB, flagz):
    return '1010010' + _encode_reg(rA) + _encode_reg(rB) + '1' + _encode_num(flagz, 2) + '0000000'

def assemble_sr(rA, rB, rC, *args):
    return '0101001' + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + '0000' + ('1' if len(args) else '0')

def assemble_sri(rA, rB, imm, *args):
    return '0111001' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')

def assemble_srim(rA, rB, imm, *args):
    return '0111011' + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + '00' + ('1' if len(args) else '0')


def assemble_srm(rA, rB, rC, *args):
    "Fish"
    return "0101011" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")

def assemble_sts(rA, rB, offset, reg_count):
    "Fish"
    return "1011000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "00" + \
           _encode_offset(offset) + "000"

def assemble_stsl(rA, rB, offset, reg_count):
    "Fish"
    return "1011000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "01" + \
           _encode_offset(offset) + "000"

def assemble_stsd(rA, rB, offset, reg_count):
    "Fish"
    return "1011000" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "10" + \
           _encode_offset(offset) + "000"

def assemble_stt(rA, rB, offset, reg_count):
    "Fish"
    return "1011010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "00" + \
           _encode_offset(offset) + "000"

def assemble_sttl(rA, rB, offset, reg_count):
    "Fish"
    return "1011010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "01" + \
           _encode_offset(offset) + "000"

def assemble_sttd(rA, rB, offset, reg_count):
    "Fish"
    return "1011010" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "10" + \
           _encode_offset(offset) + "000"

def assemble_stw(rA, rB, offset, reg_count):
    "Fish"
    return "1011001" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "00" + \
           _encode_offset(offset) + "000"

def assemble_stwl(rA, rB, offset, reg_count):
    "Fish"
    return "1011001" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "01" + \
           _encode_offset(offset) + "000"

def assemble_stwd(rA, rB, offset, reg_count):
    "Fish"
    return "1011001" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg_count(reg_count, 5) + "10" + \
           _encode_offset(offset) + "000"




# T
# No instruction starts with T

# U

# V

# W


def assemble_wt(*args):
    "Fish"
    return "101000000010000000"


# X


def assemble_xr(rA, rB, rC, *args):
    "Fish"
    return "0011100" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")


def assemble_xri(rA, rB, imm, *args):
    "Fish"
    return "0011100" + _encode_reg(rA) + _encode_reg(rB) + _encode_num(imm, 7) + "01" + ("1" if len(args) else "0")


def assemble_xrm(rA, rB, rC, *args):
    "Fish"
    return "0011110" + _encode_reg(rA) + _encode_reg(rB) + _encode_reg(rC) + "0000" + ("1" if len(args) else "0")


# Y

# Z

def assemble_zes(rA, rB, *args):
    "Fish"
    return "101000001001" + _encode_reg(rA) + _encode_reg(rB) + "00000"


def assemble_zew(rA, rB, *args):
    "Fish"
    return "101000001010" + _encode_reg(rA) + _encode_reg(rB) + "00000"


def my_ua_next_byte(cmd):
   b = get_full_byte(cmd.ea + cmd.size)
   cmd.size += 1
   return b

def get_ra_27(mcode):
   return (mcode >> (27-12)) & 0x1f

def get_rb_27(mcode):
   return (mcode >> (27-17)) & 0x1f

def get_rc_27(mcode):
   return (mcode >> (27-22)) & 0x1f

def append_next_byte(mcode, cmd):
   b2 = my_ua_next_byte(cmd)
   mcode = (mcode << 9) + b2
   return mcode

class BadMnemonic(Exception):
   def __init__(self, m):
       self.mnem = m

# ----------------------------------------------------------------------
class clemency_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 0xdc25

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 9

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 9

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['clemency']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Clemency Processor (Defcon 25)']

    # register names
    regNames = [
        # General purpose registers
        "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
        "R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18", "R19",
        "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27", "R28", "ST",
        "RA", "PC", "FL",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(regNames))
    regsNum = len(regNames)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    regFirstSreg = regNames.index("CS") # index of CS
    regLastSreg = regNames.index("DS") # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    regCodeSreg = regNames.index("CS")
    regDataSreg = regNames.index("DS")

    # for storing ML MH stuff
    mHelper = {}
    for i in range(31):
        mHelper[i] = None

    # Array of typical code start sequences (optional)
    #codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    #retcodes = []

    def ifind(self, mnem):
        ins = clemency_processor_t.instruc
        lo = 0
        hi = len(ins)
        while lo < hi:
            mid = (lo + hi) // 2
            m = ins[mid]['name']
            if m == mnem:
                return mid
            elif m > mnem:
                hi = mid
            else:
                lo = mid + 1
        raise BadMnemonic(mnem)

    # Array of instructions
    instruc = [
        {"name": "AD", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADC", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADCI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADCIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADCM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADF", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ADM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "AN", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ANI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ANM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "B", "feature": CF_USE1 | CF_JUMP | CF_STOP},
        {"name": "BE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BF", "feature": CF_CHG1 | CF_USE2},
        {"name": "BFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "BG", "feature": CF_USE1 | CF_JUMP},
        {"name": "BGE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BL", "feature": CF_USE1 | CF_JUMP},
        {"name": "BLE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BN", "feature": CF_USE1 | CF_JUMP},
        {"name": "BNO", "feature": CF_USE1 | CF_JUMP},
        {"name": "BNS", "feature": CF_USE1 | CF_JUMP},
        {"name": "BO", "feature": CF_USE1 | CF_JUMP},
        {"name": "BR", "feature": CF_USE1 | CF_JUMP | CF_STOP},
        {"name": "BRA", "feature": CF_USE1 | CF_JUMP | CF_STOP},
        {"name": "BRE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRG", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRGE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRL", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRLE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRN", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRNO", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRNS", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRO", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRR", "feature": CF_USE1 | CF_JUMP | CF_STOP},
        {"name": "BRS", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRSG", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRSGE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRSL", "feature": CF_USE1 | CF_JUMP},
        {"name": "BRSLE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BS", "feature": CF_USE1 | CF_JUMP},
        {"name": "BSG", "feature": CF_USE1 | CF_JUMP},
        {"name": "BSGE", "feature": CF_USE1 | CF_JUMP},
        {"name": "BSL", "feature": CF_USE1 | CF_JUMP},
        {"name": "BSLE", "feature": CF_USE1 | CF_JUMP},
        {"name": "C", "feature": CF_USE1 | CF_CALL},
        {"name": "CAA", "feature": CF_USE1 | CF_CALL},
        {"name": "CAR", "feature": CF_USE1 | CF_CALL},
        {"name": "CE", "feature": CF_USE1 | CF_CALL},
        {"name": "CG", "feature": CF_USE1 | CF_CALL},
        {"name": "CGE", "feature": CF_USE1 | CF_CALL},
        {"name": "CL", "feature": CF_USE1 | CF_CALL},
        {"name": "CLE", "feature": CF_USE1 | CF_CALL},
        {"name": "CM", "feature": CF_USE1 | CF_USE2},
        {"name": "CMF", "feature": CF_USE1 | CF_USE2},
        {"name": "CMFM", "feature": CF_USE1 | CF_USE2},
        {"name": "CMI", "feature": CF_USE1 | CF_USE2},
        {"name": "CMIM", "feature": CF_USE1 | CF_USE2},
        {"name": "CMM", "feature": CF_USE1 | CF_USE2},
        {"name": "CN", "feature": CF_USE1 | CF_CALL},
        {"name": "CNO", "feature": CF_USE1 | CF_CALL},
        {"name": "CNS", "feature": CF_USE1 | CF_CALL},
        {"name": "CO", "feature": CF_USE1 | CF_CALL},
        {"name": "CR", "feature": CF_USE1 | CF_CALL},
        {"name": "CRE", "feature": CF_USE1 | CF_CALL},
        {"name": "CRG", "feature": CF_USE1 | CF_CALL},
        {"name": "CRGE", "feature": CF_USE1 | CF_CALL},
        {"name": "CRL", "feature": CF_USE1 | CF_CALL},
        {"name": "CRLE", "feature": CF_USE1 | CF_CALL},
        {"name": "CRN", "feature": CF_USE1 | CF_CALL},
        {"name": "CRNO", "feature": CF_USE1 | CF_CALL},
        {"name": "CRNS", "feature": CF_USE1 | CF_CALL},
        {"name": "CRO", "feature": CF_USE1 | CF_CALL},
        {"name": "CRS", "feature": CF_USE1 | CF_CALL},
        {"name": "CRSG", "feature": CF_USE1 | CF_CALL},
        {"name": "CRSGE", "feature": CF_USE1 | CF_CALL},
        {"name": "CRSL", "feature": CF_USE1 | CF_CALL},
        {"name": "CRSLE", "feature": CF_USE1 | CF_CALL},
        {"name": "CS", "feature": CF_USE1 | CF_CALL},
        {"name": "CSG", "feature": CF_USE1 | CF_CALL},
        {"name": "CSGE", "feature": CF_USE1 | CF_CALL},
        {"name": "CSL", "feature": CF_USE1 | CF_CALL},
        {"name": "CSLE", "feature": CF_USE1 | CF_CALL},
        {"name": "DBRK", "feature": CF_STOP},
        {"name": "DI", "feature": CF_USE1},
        {"name": "DMT", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DV", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVF", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVIS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVISM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "DVSM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "EI", "feature": CF_USE1},
        {"name": "FTI", "feature": CF_CHG1 | CF_USE2},
        {"name": "FTIM", "feature": CF_CHG1 | CF_USE2},
        {"name": "HT", "feature": CF_STOP},
        {"name": "IR", "feature": CF_STOP},
        {"name": "ITF", "feature": CF_CHG1 | CF_USE2},
        {"name": "ITFM", "feature": CF_CHG1 | CF_USE2},
        {"name": "LDS", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDSD", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDSI", "feature": CF_CHG1 | CF_USE2},
        {"name": "LDT", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDTD", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDTI", "feature": CF_CHG1 | CF_USE2},
        {"name": "LDW", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDWD", "feature": CF_CHG1 | CF_USE2},
#        {"name": "LDWI", "feature": CF_CHG1 | CF_USE2},
        {"name": "MD", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDF", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDIS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDISM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MDSM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MH", "feature": CF_CHG1 | CF_USE2},
        {"name": "MI", "feature": CF_CHG1 | CF_USE2},
        {"name": "ML", "feature": CF_CHG1 | CF_USE2},
        {"name": "MS", "feature": CF_CHG1 | CF_USE2},
        {"name": "MU", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUF", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUIS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUISM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUS", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "MUSM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "NG", "feature": CF_CHG1 | CF_USE2},
        {"name": "NGF", "feature": CF_CHG1 | CF_USE2},
        {"name": "NGFM", "feature": CF_CHG1 | CF_USE2},
        {"name": "NGM", "feature": CF_CHG1 | CF_USE2},
        {"name": "NT", "feature": CF_CHG1 | CF_USE2},
        {"name": "NTM", "feature": CF_CHG1 | CF_USE2},
        {"name": "OR", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ORI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ORM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RE", "feature": CF_STOP},
        {"name": "RF", "feature": CF_CHG1},
        {"name": "RL", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RLI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RLIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RLM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RMP", "feature": CF_CHG1 | CF_USE2},
        {"name": "RND", "feature": CF_CHG1},
        {"name": "RNDM", "feature": CF_CHG1},
        {"name": "RR", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RRI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RRIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "RRM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SA", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SAI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SAIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SAM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SB", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBC", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBCI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBCIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBCM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBF", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBFM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SBM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SES", "feature": CF_CHG1 | CF_USE2},
        {"name": "SEW", "feature": CF_CHG1 | CF_USE2},
        {"name": "SF", "feature": CF_USE1},
        {"name": "SL", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SLI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SLIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SLM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SMP", "feature": CF_USE1 | CF_USE2 | CF_USE3},
        {"name": "SR", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SRI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SRIM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "SRM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "STS", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STSD", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STSI", "feature": CF_USE1 | CF_CHG2},
        {"name": "STT", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STTD", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STTI", "feature": CF_USE1 | CF_CHG2},
        {"name": "STW", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STWD", "feature": CF_USE1 | CF_CHG2},
#        {"name": "STWI", "feature": CF_USE1 | CF_CHG2},
        {"name": "WT", "feature": 0},
        {"name": "XR", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "XRI", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "XRM", "feature": CF_CHG1 | CF_USE2 | CF_USE3},
        {"name": "ZES", "feature": CF_CHG1 | CF_USE2},
        {"name": "ZEW", "feature": CF_CHG1 | CF_USE2}
    ]

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 5

    # If the FIXUP_VHIGH and FIXUP_VLOW fixup types are supported
    # then the number of bits in the HIGH part. For example,
    # SPARC will have here 22 because it has HIGH22 and LOW10 relocations.
    # See also: the description of PR_FULL_HIFXP bit
    # (optional)
    high_fixup_bits = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        'badworks': [6, 11],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler


    # ----------------------------------------------------------------------
    # The following callbacks are optional.
	# *** Please remove the callbacks that you don't plan to implement ***

#    def header(self):
#        """function to produce start of disassembled text"""
#        pass

#    def footer(self):
#        """function to produce end of disassembled text"""
#        pass

    def segstart(self, ea):
        """function to produce start of segment"""
        pass

    def segend(self, ea):
        """function to produce end of segment"""
        pass

    def assumes(self, ea):
        """function to produce assume directives"""
        pass

    def notify_term(self):
        """called when the processor module is unloading"""
        pass

    def notify_setup_til(self):
        """Setup default type libraries (called after loading a new file into the database)
        The processor module may load tils, setup memory model and perform other actions required to set up the type system
        @return: None
        """
        pass

    def notify_newprc(self, nproc):
        """
        Before changing proccesor type
        nproc - processor number in the array of processor names
        return 1-ok,0-prohibit
        """
        return 1

    def notify_newfile(self, filename):
        """A new file is loaded (already)"""
        pass

    def notify_oldfile(self, filename):
        """An old file is loaded (already)"""
        pass

    def notify_newbinary(self, filename, fileoff, basepara, binoff, nbytes):
        """
        Before loading a binary file
         args:
          filename  - binary file name
          fileoff   - offset in the file
          basepara  - base loading paragraph
          binoff    - loader offset
          nbytes    - number of bytes to load
        Returns nothing
        """
        pass

    def notify_undefine(self, ea):
        """
        An item in the database (insn or data) is being deleted
        @param args: ea
        @return: >0-ok, <=0 - the kernel should stop
                 if the return value is positive:
                     bit0 - ignored
                     bit1 - do not delete srareas at the item end
        """
        return 1

    def notify_endbinary(self, ok):
        """
         After loading a binary file
         args:
          ok - file loaded successfully?
        """
        pass

    
    #
    # ADD HANDLERS ABOVE HERE
    #
    
    def notify_assemble(self, ea, cs, ip, use32, line):
        global _pc
        _pc = ea
        line = line.split(";")[0].strip()  # supports comments
        if not line:
            return ''
    
        line = re.sub(r"\[\s*([^,\+]*?)\s*\]", r"[\1 + 0, 1]", line)
        line = re.sub(r"\[\s*([^,\+]*?)\s*,\s*([^,\+]*?)\s*\]", r"[\1 + 0, \2]", line)
        line = re.sub(r"\[\s*([^,\+]*?)\s*\+\s*([^,\+]*?)\s*\]", r"[\1 + \2, 1]", line)
    
        # default parsing rule: ignore brackets, comma and plus sign, and split by space
        line = re.sub('[\\[\\]+,]', ' ', line)
    
        parts = line.split()
        op = parts[0]
        args = parts[1:]
        if op.endswith("."):
            args.append("UL")
            op = op.strip('.')
    
        try:
            assembler = globals()['assemble_'+op.lower()]
        except KeyError:
            raise Exception("Unsupported instruction: %s" % op)
        a = assembler(*args)
    
        assert len(a) % 9 == 0
        res = encode_me(a)
        i = 0
        while len(res) >= 9:
            PatchByte(ea + i, int(res[:9], 2))
            i += 1
            res = res[9:]
        return ''
    

    def notify_savebase(self):
        """The database is being saved. Processor module should save its local data"""
        pass

    '''
    def data_out(self, ea):
        """
        Generate text represenation of data items
        This function MAY change the database and create cross-references, etc.
        """
        if GetStringType(ScreenEA()) == 3:
            buf = init_output_buffer(1024)
            out_keyword("db")
            OutChar(' ')
            out_symbol('\'')
            r = ''
            for i in range(ItemSize(ea)):
               b = Byte(ea + i)
               if b == 0:
                  break
               r += chr(b)
            out_snprintf("%s", r)
            out_symbol('\'')
            out_symbol(',')
            OutChar(' ')
            OutLong(0, 10)
            term_output_buffer()
    
            cvar.gl_comm = 1
            MakeLine(buf)
        else:
            intel_data(ea)
    '''

    def cmp_opnd(self, op1, op2):
        """
        Compare instruction operands.
        Returns 1-equal,0-not equal operands.
        """
        return False

    def can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return True

    def translate(self, base, offset):
        """
        Translation function for offsets
        Currently used in the offset display functions
        to calculate the referenced address
        Returns: ea_t
        """
        return BADADDR

    def set_idp_options(self, keyword, type, value):
        """
        Set IDP-specific option
        args:
          keyword - the option name
                    or empty string (check type when 0 below)
          type    - one of
                      IDPOPT_STR  string constant
                      IDPOPT_NUM  number
                      IDPOPT_BIT  zero/one
                      IDPOPT_FLT  float
                      IDPOPT_I64  64bit number
                      0 -> You should display a dialog to configure the processor module
          value   - the actual value
        Returns:
           IDPOPT_OK        ok
           IDPOPT_BADKEY    illegal keyword
           IDPOPT_BADTYPE   illegal type of value
           IDPOPT_BADVALUE  illegal value (bad range, for example)
        otherwise return a string containing the error messages
        """
        return idaapi.IDPOPT_OK

    def gen_map_file(self, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - empty file, -1 - write error
        """
        r1 = qfile.write("Line 1\n")
        r2 = qfile.write("Line 2\n!")
        return 2 # two lines

    def create_func_frame(self, func_ea):
        """
        Create a function frame for a newly created function.
        Set up frame size, its attributes etc.
        """
        return False

    def is_far_jump(self, icode):
        """
        Is indirect far jump or call instruction?
        meaningful only if the processor has 'near' and 'far' reference types
        """
        return False

    def is_align_insn(self, ea):
        """
        Is the instruction created only for alignment purposes?
        Returns: number of bytes in the instruction
        """
        return 0

    def outspec(self, ea, segtype):
        """
        Generate text representation of an item in a special segment
        i.e. absolute symbols, externs, communal definitions etc.
        Returns: 1-overflow, 0-ok
        """
        return 0

    def get_frame_retsize(self, func_ea):
        """
        Get size of function return address in bytes
        If this function is absent, the kernel will assume
             4 bytes for 32-bit function
             2 bytes otherwise
        """
        return 3

    def is_switch(self, swi):
        """
        Find 'switch' idiom.
        Fills 'si' structure with information

        @return: Boolean (True if switch was found and False otherwise)
        """
        return False

    def is_sp_based(self, op):
        """
        Check whether the operand is relative to stack pointer or frame pointer.
        This function is used to determine how to output a stack variable
        This function may be absent. If it is absent, then all operands
        are sp based by default.
        Define this function only if some stack references use frame pointer
        instead of stack pointer.
        returns flags:
          OP_FP_BASED   operand is FP based
          OP_SP_BASED   operand is SP based
          OP_SP_ADD     operand value is added to the pointer
          OP_SP_SUB     operand value is substracted from the pointer
        """
        return idaapi.OP_FP_BASED

    def notify_add_func(self, func_ea):
        """
        The kernel has added a function.
        @param func_ea: function start EA
        @return: Nothing
        """
        pass

    def notify_del_func(self, func_ea):
        """
        The kernel is about to delete a function
        @param func_ea: function start EA
        @return: 1-ok,<=0-do not delete
        """
        return 1

    auto_comments = {
       "AD" : "add",
       "ADC" : "add with carry",
       "ADCI" : "add immediate with carry",
       "ADCIM" : "add immediate multi reg with",
       "ADCM" : "add multi reg with carry",
       "ADF" : "add floating point",
       "ADFM" : "add floating point multi reg",
       "ADI" : "add immediate",
       "ADIM" : "add immediate multi reg",
       "ADM" : "add multi reg",
       "AN" : "and",
       "ANI" : "and immediate",
       "ANM" : "and multi reg",
       "B" : "branch",
       "BE" : "branch on equal",
       "BF" : "bit flip",
       "BFM" : "bit flip multi reg",
       "BG" : "branch greater than",
       "BGE" : "branch greater than or equal",
       "BL" : "branch less than",
       "BLE" : "branch less than or equal",
       "BN" : "branch not equal",
       "BNO" : "branch not overflow",
       "BNS" : "branch not signed",
       "BO" : "branch on overflow",
       "BR" : "branch register",
       "BRA" : "branch absolute",
       "BRE" : "branch register on equal",
       "BRG" : "branch register on greater than",
       "BRGE" : "branch register on greater than or equal",
       "BRL" : "branch register on less than",
       "BRLE" : "branch register on less than or equal",
       "BRN" : "branch register on not equal",
       "BRNO" : "branch register on not overflow",
       "BRNS" : "branch register on not signed",
       "BRO" : "branch register on overflow",
       "BRR" : "branch relative",
       "BRS" : "branch register on signed",
       "BRSG" : "branch register on signed greater than",
       "BRSGE" : "branch register on signed greater than or equal",
       "BRSL" : "branch register on signed less than",
       "BRSLE" : "branch register on signed less than or equal",
       "BS" : "branch on signed",
       "BSG" : "branch on signed greater than",
       "BSGE" : "branch on signed greater than or equal",
       "BSL" : "branch on signed less than",
       "BSLE" : "branch on signed less than or equal",
       "C" : "call",
       "CAA" : "call absolute",
       "CAR" : "call relative",
       "CE" : "call on equal",
       "CG" : "call greater than",
       "CGE" : "call greater than or equal",
       "CL" : "call less than",
       "CLE" : "call less than or equal",
       "CM" : "compare",
       "CMF" : "compare floating point",
       "CMFM" : "compare floating point multi reg",
       "CMI" : "compare immediate",
       "CMIM" : "compare immediate multi reg",
       "CMM" : "compare multi reg",
       "CN" : "call not equal",
       "CNO" : "call not overflow",
       "CNS" : "call not signed",
       "CO" : "call on overflow",
       "CR" : "call register",
       "CRE" : "call register on equal",
       "CRG" : "call register greater than",
       "CRGE" : "call register greater than or equal",
       "CRL" : "call register less than",
       "CRLE" : "call register less than or equal",
       "CRN" : "call register not equal",
       "CRNO" : "call register not overflow",
       "CRNS" : "call register not signed",
       "CRO" : "call register on overflow",
       "CRS" : "call register on signed",
       "CRSG" : "call register on signed greater than",
       "CRSGE" : "call register on signed greater than or equal",
       "CRSL" : "call register on signed less than",
       "CRSLE" : "call register on signed less than or equal",
       "CS" : "call on signed",
       "CSG" : "call on signed greater than",
       "CSGE" : "call on signed greater than or equal",
       "CSL" : "call on signed less than",
       "CSLE" : "call on signed less than or equal",
       "DBRK" : "debug break",
       "DI" : "disable interrupts",
       "DMT" : "direct memory transfer",
       "DV" : "divide",
       "DVF" : "divide floating point",
       "DVFM" : "divide floating point multi reg",
       "DVI" : "divide immediate",
       "DVIM" : "divide immediate multi reg",
       "DVIS" : "divide immediate signed",
       "DVISM" : "divide immediate signed multi",
       "DVM" : "divide multi reg",
       "DVS" : "divide signed",
       "DVSM" : "divide signed multi reg",
       "EI" : "enable interrupts",
       "FTI" : "float to integer",
       "FTIM" : "float to integer multi reg",
       "HT" : "halt",
       "IR" : "interrupt return",
       "ITF" : "integer to float",
       "ITFM" : "integer to float multi reg",
       "LDS" : "load single",
#       "LDSD" : "load single and decrement",
#       "LDSI" : "load single and increment",
       "LDT" : "load tri",
#       "LDTD" : "load tri and decrement",
#       "LDTI" : "load tri and increment",
       "LDW" : "load word",
#       "LDWD" : "load word and decrement",
#       "LDWI" : "load word and increment",
       "MD" : "modulus",
       "MDF" : "modulus floating point",
       "MDFM" : "modulus floating point multi reg",
       "MDI" : "modulus immediate",
       "MDIM" : "modulus immediate multi reg",
       "MDIS" : "modulus immediate signed",
       "MDISM" : "modulus immediate signed multi",
       "MDM" : "modulus multi reg",
       "MDS" : "modulus signed",
       "MDSM" : "modulus signed multi reg",
       "MH" : "move high",
       "MI" : "move immediate tri-byte (macro for ML/MH)",
       "ML" : "move low",
       "MS" : "move low signed",
       "MU" : "multiply",
       "MUF" : "multiply floating point",
       "MUFM" : "multiply floating point multi reg",
       "MUI" : "multiply immediate",
       "MUIM" : "multiply immediate multi reg",
       "MUIS" : "multiply immediate signed",
       "MUISM" : "multiply immediate signed multi",
       "MUM" : "multiply multi reg",
       "MUS" : "multiply signed",
       "MUSM" : "multiply signed multi reg",
       "NG" : "negate",
       "NGF" : "negate floating point",
       "NGFM" : "negate floating point multi reg",
       "NGM" : "negate multi reg",
       "NT" : "not",
       "NTM" : "not multi reg",
       "OR" : "or",
       "ORI" : "or immediate",
       "ORM" : "or multi reg",
       "RE" : "return",
       "RF" : "read flags",
       "RL" : "rotate left",
       "RLI" : "rotate left immediate",
       "RLIM" : "rotate left immediate multi reg",
       "RLM" : "rotate left multi reg",
       "RMP" : "read memory protection",
       "RND" : "random",
       "RNDM" : "random multi reg",
       "RR" : "rotate right",
       "RRI" : "rotate right immediate",
       "RRIM" : "rotate right immediate multi reg",
       "RRM" : "rotate right multi reg",
       "SA" : "shift arithemetic right",
       "SAI" : "shift arithemetic right immediate",
       "SAIM" : "shift arithemetic right immediate multi reg",
       "SAM" : "shift arithemetic right multi reg",
       "SB" : "subtract",
       "SBC" : "subtract with carry",
       "SBCI" : "subtract immediate with carry",
       "SBCIM" : "subtract immediate multi reg",
       "SBCM" : "subtract multi reg with carry",
       "SBF" : "subtract floating point",
       "SBFM" : "subtract floating point multi reg",
       "SBI" : "subtract immediate",
       "SBIM" : "subtract immediate multi reg",
       "SBM" : "subtract multi reg",
       "SES" : "sign extend single",
       "SEW" : "sign extend word",
       "SF" : "set flags",
       "SL" : "shift left",
       "SLI" : "shift left immediate",
       "SLIM" : "shift left immediate multi reg",
       "SLM" : "shift left multi reg",
       "SMP" : "set memory protection",
       "SR" : "shift right",
       "SRI" : "shift right immediate",
       "SRIM" : "shift right immediate multi reg",
       "SRM" : "shift right multi reg",
       "STS" : "store single",
#       "STSD" : "store single and decrement",
#       "STSI" : "store single and increment",
       "STT" : "store tri",
#       "STTD" : "store tri and decrement",
#       "STTI" : "store tri and increment",
       "STW" : "store word",
#       "STWD" : "store word and decrement",
#       "STWI" : "store word and increment",
       "WT" : "wait",
       "XR" : "xor",
       "XRI" : "xor immediate",
       "XRM" : "xor multi reg",
       "ZES" : "zero extend single",
       "ZEW" : "zero extend word"
    }
    
    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        mnem = self.instruc[self.cmd.itype]['name']
        if mnem in self.auto_comments:
           return self.auto_comments[mnem]
        return None

    def notify_create_switch_xrefs(self, jumpea, swi):
        """Create xrefs for a custom jump table
           @param jumpea: address of the jump insn
           @param swi: switch information
           @return: None
        """
        pass

    def notify_calc_step_over(self, ip):
        """
        Calculate the address of the instruction which will be
        executed after "step over". The kernel will put a breakpoint there.
        If the step over is equal to step into or we can not calculate
        the address, return BADADDR.
        args:
          ip - instruction address
        returns: target or BADADDR
        """
        return idaapi.BADADDR

    def notify_may_be_func(self, state):
        """
        can a function start here?
        the instruction is in 'cmd'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """
        return 0

    def notify_str2reg(self, regname):
        """
        Convert a register name to a register number
          args: regname
          Returns: register number or -1 if not avail
          The register number is the register index in the regNames array
          Most processor modules do not need to implement this callback
          It is useful only if ph.regNames[reg] does not provide
          the correct register names
        """
        if regname in self.regNames:
           return self.regNames.index(regname)
        return -1

    def notify_is_sane_insn(self, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'cmd'
        returns: 1-ok, <=0-no, the instruction isn't
        likely to appear in the program
        """
        return 0

    def notify_func_bounds(self, code, func_ea, max_func_end_ea):
        """
        find_func_bounds() finished its work
        The module may fine tune the function bounds
        args:
          possible code - one of FIND_FUNC_XXX (check find_func_bounds)
          func_ea - func start ea
          max_func_end_ea (from the kernel's point of view)
        returns: possible_return_code
        """
        return FIND_FUNC_OK

#if we leave these uncommented we won't get function headers
#    def asm_func_header(self, func_ea):
#        """generate function header lines"""
#        pass

#    def asm_func_footer(self, func_ea):
#        """generate function footer lines"""
#        pass

    def asm_get_type_name(self, flag, ea_or_id):
        """
        Get name of type of item at ea or id.
        (i.e. one of: byte,word,dword,near,far,etc...)
        """
        if isCode(flag):
            pfn = get_func(ea_or_id)
            # return get func name
        elif isWord(flag):
            return "word"
        return ""

    def notify_init(self, idp_file):
        # init returns non-zero on success
        return 1

    def notify_outlabel(self, ea, colored_name):
        """
        The kernel is going to generate an instruction label line
        or a function header
        args:
          ea - instruction address
          colored_name -
        If returns value <=0, then the kernel should not generate the label
        """
        return 1

    def notify_rename(self, ea, new_name):
        """
        The kernel is going to rename a byte
        args:
          ea -
          new_name -
        If returns value <=0, then the kernel should not rename it
        """
        return 1

    def notify_may_show_sreg(self, ea):
        """
        The kernel wants to display the segment registers
        in the messages window.
        args:
          ea
        if this function returns 0
        then the kernel will not show
        the segment registers.
        (assuming that the module have done it)
        """
        return 1

    def notify_coagulate(self, start_ea):
        """
        Try to define some unexplored bytes
        This notification will be called if the
        kernel tried all possibilities and could
        not find anything more useful than to
        convert to array of bytes.
        The module can help the kernel and convert
        the bytes into something more useful.
        args:
          start_ea -
        returns: number of converted bytes
        """
        return 0

    def notify_closebase(self):
        """
        The database will be closed now
        """
        pass

    def notify_load_idasgn(self, short_sig_name):
        """
        FLIRT signature have been loaded for normal processing
        (not for recognition of startup sequences)
        args:
          short_sig_name
        """
        pass

    def notify_auto_empty(self):
        """
        Info: all analysis queues are empty.
        This callback is called once when the
        initial analysis is finished. If the queue is
        not empty upon the return from this callback,
        it will be called later again
        """
        pass

    def notify_is_call_insn(self, ea):
        """
        Is the instruction a "call"?
        args
          ea  - instruction address
        returns: 1-unknown, 0-no, 2-yes
        """
        #m = GetMnem(ea)
        #return m is not None and m.startswith("C") and not m.startswith("CM")
        return 1

    def notify_is_ret_insn(self, ea, strict):
        """
        Is the instruction a "return"?
        ea  - instruction address
        strict - 1: report only ret instructions
                 0: include instructions like "leave"
                    which begins the function epilog
        returns: 1-unknown, 0-no, 2-yes
        """
        #return GetMnem(ea) == "RE"
        return 1

    def notify_kernel_config_loaded(self):
        """
        This callback is called when ida.cfg is parsed
        """
        pass

    def notify_is_alloca_probe(self, ea):
        """
        Does the function at 'ea' behave as __alloca_probe?
        args:
          ea
        returns: 2-yes, 1-false
        """
        return 1

    def notify_out_src_file_lnnum(self, filename, lnnum):
        """
        Callback: generate analog of
        #line "file.c" 123
        directive.
        args:
          file - source file (may be NULL)
          lnnum - line number
        returns: 2-directive has been generated
        """
        return 1

    def notify_is_insn_table_jump(self):
        """
        Callback: determine if instruction is a table jump or call
        If CF_JUMP bit can not describe all kinds of table
        jumps, please define this callback.
        It will be called for insns with CF_JUMP bit set.
        input: cmd structure contains the current instruction
        returns: 1-yes, 0-no
        """
        return 0

    def notify_auto_empty_finally(self):
        """
        Info: all analysis queues are empty definitively
        """
        ss = strwinsetup_t()
        ss.minlen = 7
        ss.strtypes = 9
        ss.ignore_heads = 1
        ss.ea1 = 0
        
        SetLongPrm(INF_STRTYPE, ASCSTR_UNICODE)

        set_strlist_options(ss)
        refresh_strlist(0, BADADDR)
        si = string_info_t()
        for i in range(get_strlist_qty()):
           if get_strlist_item(i, si):
              if not isCode(GetFlags(si.ea)):
                 ea = get_start(si.ea)
                 s = make_str(ea)
                 hd = ItemHead(si.ea)
                 do_unknown(hd, 0)
                 make_ascii_string(ea, len(s) + 1, ASCSTR_UNICODE)
                 MakeRptCmt(ea, "\"%s\"" % s)

    def notify_is_indirect_jump(self):
        """
        Callback: determine if instruction is an indrect jump
        If CF_JUMP bit can not describe all jump types
        jumps, please define this callback.
        input: cmd structure contains the current instruction
        returns: 1-use CF_JUMP, 2-no, 3-yes
        """
        return 1

    def notify_determined_main(self, main_ea):
        """
        The main() function has been determined
        """
        pass

    def notify_validate_flirt_func(self, ea, funcname):
        """
        flirt has recognized a library function
        this callback can be used by a plugin or proc module
        to intercept it and validate such a function
        args:
          start_ea
          funcname
        returns: -1-do not create a function,
                  1-function is validated
        the idp module is allowed to modify 'cmd'
        """
        return 1

    def notify_set_proc_options(self, options):
        """
        called if the user specified an option string in the command line:
        -p<processor name>:<options>
        can be used for e.g. setting a processor subtype
        also called if option string is passed to set_processor_type()
        and IDC's SetProcessorType()
        args:
          options
        returns: <0 - bad option string
        """
        return 1

    def notify_newseg(self, start_ea, segm_name, segm_class):
        """
        A new segment is about to be created
        args:
          start_ea
          segm_name
          segm_class
        return 1-ok, 0-segment should not be created
        """
        return 1

    def notify_auto_queue_empty(self, type):
        """
        One analysis queue is empty.
        args:
          atype_t type
        This callback can be called many times, so
        only the autoMark() functions can be used from it
        (other functions may work but it is not tested)
        """
        return 1

    def notify_gen_regvar_def(self, canon, user, cmt):
        """
        generate register variable definition line
        args:
          canon - canonical register name (case-insensitive)
          user - user-defined register name
          cmt - comment to appear near definition
        returns: 0-ok
        """
        return 1

    def notify_setsgr(self, start_ea, end_ea, regnum, value, old_value, tag):
        """
        The kernel has changed a segment register value
        args:
          startEA
          endEA
          regnum
          value
          old_value
          uchar tag (SR_... values)
        returns: 1-ok, 0-error
        """
        return 1

    def notify_set_compiler(self):
        """
        The kernel has changed the compiler information
        """
        pass

    def notify_is_basic_block_end(self, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'cmd'
        args:
          call_insn_stops_block
          returns: 1-unknown, 0-no, 2-yes
        """
        return 1

    def notify_make_code(self, ea, size):
        """
        An instruction is being created
        args:
          ea
          size
        returns: 1-ok, <=0-the kernel should stop
        """
        return 1

    def notify_make_data(self, ea, flags, tid, size):
        """
        A data item is being created
        args:
          ea
          flags
          tid
          size
        returns: 1-ok, <=0-the kernel should stop
        """
        return 1

    def notify_moving_segm(self, start_ea, segm_name, segm_class, to_ea, flags):
        """
        May the kernel move the segment?
        args:
          start_ea, segm_name, segm_class - segment to move
          to_ea   - new segment start address
          int flags - combination of MSF_... bits
        returns: 1-yes, <=0-the kernel should stop
        """
        return 1

    def notify_move_segm(self, from_ea, start_ea, segm_name, segm_class):
        """
        A segment is moved
        Fix processor dependent address sensitive information
        args:
          from_ea  - old segment address
          start_ea, segm_name, segm_class - moved segment
        returns: nothing
        """
        pass

    def notify_verify_noreturn(self, func_start_ea):
        """
        The kernel wants to set 'noreturn' flags for a function
        args:
          func_start_ea
        Returns: 1-ok, any other value-do not set 'noreturn' flag
        """
        return 1

    def notify_verify_sp(self, func_start_ea):
        """
        All function instructions have been analyzed
        Now the processor module can analyze the stack pointer
        for the whole function
        args:
          func_start_ea
        Returns: 1-ok, 0-bad stack pointer
        """
        return 1

    def notify_renamed(self, ea, new_name, is_local_name):
        """
        The kernel has renamed a byte
        args:
          ea
          new_name
          is_local_name
        Returns: nothing. See also the 'rename' event
        """
        pass

    def notify_set_func_start(self, pfn, new_ea):
        """
        Function chunk start address will be changed
        args:
          func_start_ea, func_end_ea
          new_ea
        Returns: 1-ok,<=0-do not change
        """
        return 1
        
    def notify_set_func_end(self, pfn, new_end_ea):
        """
        Function chunk end address will be changed
        args:
          func_start_ea, func_end_ea
          new_end_ea
        Returns: 1-ok,<=0-do not change
        """
        return 1
        
    def notify_treat_hindering_item(self, hindering_item_ea, new_item_flags, new_item_ea, new_item_length):
        """
        An item hinders creation of another item
        args:
          hindering_item_ea
          new_item_flags
          new_item_ea
          new_item_length
        Returns: 1-no reaction, <=0-the kernel may delete the hindering item
        """
        return 1

    def notify_get_operand_string(self, opnum):
        """
        Request text string for operand (cli, java, ...)
        args:
          opnum - the operand number; -1 means any string operand
        (cmd structure must contain info for the desired insn)
        Returns: requested
        """
        return ""

    def notify_coagulate_dref(self, from_ea, to_ea, may_define, code_ea):
        """
        data reference is being analyzed
        args:
          from_ea, to_ea, may_define, code_ea
        plugin may correct code_ea (e.g. for thumb mode refs, we clear the last bit)
        Returns: new code_ea or -1 - cancel dref analysis
        """
        return 0

    def simplify(self):
        itype = self.cmd.itype
        if itype == self.ifind("MI"):
            imm = self.cmd.Operands[1].value
            reg = self.cmd.Operands[0].reg
            self.mHelper[reg] = imm 
            if not isHead(GetFlags(self.mHelper[reg])):
               do_unknown(ItemHead(self.mHelper[reg]), 0)
            ua_add_dref(0, self.mHelper[reg], dr_O)
            '''
            try:
                buf = init_output_buffer(1024)
                out_name_expr(self.cmd, self.mHelper[reg], BADADDR)
                term_output_buffer()
                MakeRptCmt(self.cmd.ea, buf)
                ua_add_dref(0, self.mHelper[reg], dr_R)
            except:
                pass
            '''
        elif itype == self.ifind("ML"):
            imm = self.cmd.Operands[1].value
            reg = self.cmd.Operands[0].reg
            self.mHelper[reg] = imm 
        elif itype == self.ifind("MH"):
            try:
                imm = self.cmd.Operands[1].value
                reg = self.cmd.Operands[0].reg
                self.mHelper[reg] = (imm << 10) | (self.mHelper[reg] & 0x3ff)
                '''
                buf = init_output_buffer(1024)
                out_name_expr(self.cmd, self.mHelper[reg], BADADDR)
                term_output_buffer()
                MakeRptCmt(self.cmd.ea, buf)
                '''
                if not isHead(GetFlags(self.mHelper[reg])):
                   do_unknown(ItemHead(self.mHelper[reg]), 0)
                ua_add_dref(0, self.mHelper[reg], dr_O)
            except:
                pass
        elif itype == self.ifind("LDT") or itype == self.ifind("STT"):
            try:
                off = self.cmd.Operands[1].addr
                base = self.cmd.Operands[1].phrase
                '''
                buf = init_output_buffer(1024)
                out_name_expr(self.cmd, self.mHelper[base] + off, BADADDR)
                term_output_buffer()
                MakeRptCmt(self.cmd.ea, buf)
                '''
            except:
                pass
        elif itype == self.ifind("LDS") or itype == self.ifind("STS"):
            try:
                off = self.cmd.Operands[1].addr
                base = self.cmd.Operands[1].phrase
                '''
                buf = init_output_buffer(1024)
                out_name_expr(self.cmd, self.mHelper[base] + off, BADADDR)
                term_output_buffer()
                MakeRptCmt(self.cmd.ea, buf)
                '''
            except:
                pass
        elif itype == self.ifind("LDW") or itype == self.ifind("STW"):
            try:
                off = self.cmd.Operands[1].addr
                base = self.cmd.Operands[1].phrase
                '''
                buf = init_output_buffer(1024)
                out_name_expr(self.cmd, self.mHelper[base] + off, BADADDR)
                term_output_buffer()
                MakeRptCmt(self.cmd.ea, buf)
                '''
            except:
                pass
        elif itype == self.ifind("XR"):
            try:
                ra = self.cmd.Operands[0].reg
                rb = self.cmd.Operands[1].reg
                rc = self.cmd.Operands[2].reg
                self.mHelper[ra] = self.mHelper[rc] ^ self.mHelper[rb]
            except:
                pass
        else:
            entry = self.instruc[self.cmd.itype]
            if entry['feature'] & CF_CHG1:
                ra = self.cmd.Operands[0].reg
                self.mHelper[ra] = None
        return

    # ----------------------------------------------------------------------
    # The following callbacks are mandatory
    #

    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        cmd = self.cmd
        features = cmd.get_canon_feature()
        addr = cmd.Operands[0].addr
        if (features & CF_CALL) and cmd.Operands[0].type == o_near:
            ua_add_cref(0, addr, fl_CN)
        if (features & CF_JUMP) and cmd.Operands[0].type == o_near:
            ua_add_cref(0, addr, fl_JN)
        if (cmd.get_canon_feature() & CF_STOP) == 0:
            ua_add_cref(0, cmd.ea + cmd.size, fl_F)

        '''
        if cmd.Operands[1].type == o_displ and may_create_stkvars() and cmd.Operands[1].phrase == 28:
            # var_x(SP)
            pfn = get_func(cmd.ea)
            if pfn and ua_stkvar2(cmd.Operands[1], cmd.Operands[1].addr, STKVAR_VALID_SIZE):
                op_stkvar(cmd.ea, 1)
        '''
        '''
        if may_trace_sp():
            if (features & CF_STOP) == 0:
                pfn = get_func(cmd.ea)
                if pfn and cmd.auxpref != 0:
                   if cmd.Operands[1].specval > 0 and cmd.Operands[1].phrase == 29:
                      delta = 0
                      if cmd.auxpref == 1:
                          delta = cmd.Operands[1].specval * 3
                      else:
                          delta = -cmd.Operands[1].specval * 3
                      add_auto_stkpnt2(pfn, cmd.ea + cmd.ea.size, delta)
            else:
                recalc_spd(cmd.ea) # recalculate SP register for the next insn
        '''
        self.simplify()
        return 1

    perms = ["N", "R", "RW", "RX"]

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        if op.type == o_reg:
           out_register(self.regNames[op.reg])
           if op.specval > 1:
               OutChar('-')
               out_register(self.regNames[op.reg + op.specval - 1])
        elif op.type == o_displ:
           out_symbol('[')
           out_register(self.regNames[op.phrase])
           if op.addr:
              '''
              if op.addr & 0x4000000:  #negative number
                 se = (op.addr | 0xf8000000) & 0xffffffff
                 x = struct.unpack("<i", struct.pack("<I", se))[0]
                 op.addr = x
                 op.value = x
              else:
                 op.value = op.addr
              '''
              #op.type = o_imm
#              OutValue(op, OOFS_NEEDSIGN | OOF_SIGNED);
              OutValue(op, OOFW_32 | OOF_NUMBER | OOF_SIGNED | OOFS_NEEDSIGN)
           out_symbol(']')
        elif op.type == o_near:
           out_name_expr(op, op.addr, BADADDR)
        elif op.type == o_imm:
           if op.specflag2 == 1:
              out_keyword(self.perms[op.value])
           elif op.specflag3 == 1:
              if not out_name_expr(op, op.addr, BADADDR):
                  OutValue(op, OOF_ADDR);
           else:
              if op.value & 0x4000000:  #negative number
                 se = op.value | 0xf8000000
                 op.value = struct.unpack("<i", struct.pack("<I", se))[0]
              OutValue(op, OOFW_32 | OOF_NUMBER | OOF_SIGNED)
        return True

    suffixes = ["", "I", "D", "."]

    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        buf = init_output_buffer(1024)
        cmd = self.cmd

        OutMnem(7, self.suffixes[cmd.auxpref])

        if cmd.itype != 3:
           out_one_operand(0)

           for i in range(1, 3):
               op = cmd[i]

               if op.type == o_void:
                   break
               out_symbol(',')
               OutChar(' ')
               out_one_operand(i)

        term_output_buffer()

        cvar.gl_comm = 1
        MakeLine(buf)

    conditions = ["N", "E", "L", "LE", "G", "GE", "NO", "O", "NS", "S", "SL", "SLE", "SG", "SGE", "???", ""]

    def dc_gen_2(self, cmd, mcode, mnem):
        cmd.itype = self.ifind(mnem)
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].reg = (mcode >> (27-14)) & 0x1f
        cmd.Operands[0].dtyp = dt_3byte
        cmd.Operands[1].type = o_reg
        cmd.Operands[1].reg = (mcode >> (27-19)) & 0x1f
        cmd.Operands[1].dtyp = dt_3byte

    def dc_gen_3(self, cmd, mcode, mnem):
        cmd.itype = self.ifind(mnem)
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].reg = get_ra_27(mcode)
        cmd.Operands[0].dtyp = dt_3byte
        cmd.Operands[1].type = o_reg
        cmd.Operands[1].reg = get_rb_27(mcode)
        cmd.Operands[1].dtyp = dt_3byte
        cmd.Operands[2].type = o_reg
        cmd.Operands[2].reg = get_rc_27(mcode)
        cmd.Operands[2].dtyp = dt_3byte

    def dc_gen_3_imm(self, cmd, mcode, mnem):
        cmd.itype = self.ifind(mnem)
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].reg = get_ra_27(mcode)
        cmd.Operands[1].type = o_reg
        cmd.Operands[1].reg = get_rb_27(mcode)
        cmd.Operands[2].type = o_imm
        cmd.Operands[2].value = (mcode >> 3) & 0x7f

    def dc_ad(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ADI")
        else:
            self.dc_gen_3(cmd, mcode, "AD")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_adc(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ADCI")
        else:
            self.dc_gen_3(cmd, mcode, "ADC")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_adcm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ADCIM")
        else:
            self.dc_gen_3(cmd, mcode, "ADCM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_adf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "ADF")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_adfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "ADFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_adm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ADIM")
        else:
            self.dc_gen_3(cmd, mcode, "ADM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_an(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ANI")
        else:
            self.dc_gen_3(cmd, mcode, "AN")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_anm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "ANM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_b(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cond = (mcode >> 17) & 0xf
        #print "dc_b cond at 0x%x = 0x%x" % (cmd.ea, cond)
        off = mcode & 0x1ffff
        if off & 0x10000:
            off += 0x7fe0000
        cmd.Operands[0].addr = (cmd.ea + off) & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("B" + self.conditions[cond])

    def dc_bf(self, cmd, mcode):     #and dc_ng dc_nt dc_rnd
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 0xc0
        if m == 0x80:
            self.dc_gen_2(cmd, mcode, "BF")
        elif m == 0:
            self.dc_gen_2(cmd, mcode, "NG")
        elif m == 0x40:
            self.dc_gen_2(cmd, mcode, "NT")
        elif m == 0xc0:
            cmd.Operands[0].reg = (mcode >> (27 - 14)) & 0x1f
            cmd.Operands[0].type = o_reg
            cmd.itype = self.ifind("RND")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_bfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 0xc0
        if mcode & 0x80:
            self.dc_gen_2(cmd, mcode, "BFM")
            cmd.Operands[1].specflag1 = 1
        elif m == 0:
            self.dc_gen_2(cmd, mcode, "NGM")
            cmd.Operands[1].specflag1 = 1
        elif m == 0x40:
            self.dc_gen_2(cmd, mcode, "NTM")
            cmd.Operands[1].specflag1 = 1
        elif m == 0xc0:
            self.dc_gen_2(cmd, mcode, "RNDM")
            cmd.Operands[0].reg = (mcode >> (27 - 14)) & 0x1f
            cmd.Operands[0].type = o_reg
            cmd.itype = self.ifind("RND")
        cmd.Operands[0].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_br(self, cmd, mcode):
        cond = (mcode >> 8) & 0xf
        #print "dc_br cond at 0x%x = 0x%x" % (cmd.ea, cond)
        cmd.Operands[0].reg = (mcode >> 3) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("BR" + self.conditions[cond])

    def dc_bra(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].addr = mcode & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("BRA")

    def dc_brr(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].addr = (cmd.ea + mcode) & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("BRR")

    def dc_c(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cond = (mcode >> 17) & 0xf
        #print "dc_c cond at 0x%x = 0x%x" % (cmd.ea, cond)
        off = mcode & 0x1ffff
        if off & 0x10000:
            off += 0x7fe0000
        cmd.Operands[0].addr = (cmd.ea + off) & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("C" + self.conditions[cond])

    def dc_caa(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].addr = mcode & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("CAA")

    def dc_car(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].addr = (cmd.ea + mcode) & 0x7ffffff
        cmd.Operands[0].type = o_near
        cmd.itype = self.ifind("CAR")

    def dc_cm(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 5) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = mcode & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.itype = self.ifind("CM")

    def dc_cmf(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 5) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = mcode & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.itype = self.ifind("CMF")

    def dc_cmfm(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 5) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].reg = mcode & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.Operands[1].specflag1 = 1
        cmd.itype = self.ifind("CMFM")

    def dc_cmi(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27-13)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].value = mcode & 0x3fff
        cmd.Operands[1].type = o_imm
        cmd.itype = self.ifind("CMI")

    def dc_cmim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27-13)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].value = mcode & 0x3fff
        cmd.Operands[1].type = o_imm
        cmd.Operands[1].specflag1 = 1
        cmd.itype = self.ifind("CMI")

    def dc_cmm(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 5) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].reg = mcode & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.Operands[1].specflag1 = 1
        cmd.itype = self.ifind("CMM")

    def dc_cr(self, cmd, mcode):
        cond = (mcode >> 8) & 0xf
        #print "dc_cr cond at 0x%x = 0x%x" % (cmd.ea, cond)
        cmd.Operands[0].reg = (mcode >> 3) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("CR" + self.conditions[cond])

    def dc_dbrk(self, cmd, mcode):
        cmd.itype = self.ifind("DBRK")

    def dc_di(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 1) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("DI")

    def dc_dmt(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "DMT")

    def dc_dv(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "DVI")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "DV")
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "DVIS")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "DVS")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_dvf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "DVF")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_dvfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "DVFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_dvm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "DVIM")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "DVM")
            cmd.Operands[2].specflag1 = 1
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "DVISM")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "DVSM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_ei(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 1) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("EI")

    def dc_fti(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "FTI")

    def dc_ftim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "FTIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1

    def dc_ht(self, cmd, mcode):
        cmd.itype = self.ifind("HT")

    def dc_ir(self, cmd, mcode):
        cmd.itype = self.ifind("IR")

    def dc_itf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "ITF")

    def dc_itfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "ITFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1

    def dc_ld(self, cmd, mcode, mnem):
        cmd.auxpref = (mcode >> 3) & 3
        b4 = my_ua_next_byte(cmd)
        mcode = append_next_byte(mcode, cmd)
        mcode = (mcode << 9) + b4
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (54 - 12)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].specval = ((mcode >> (54 - 22)) & 0x1f) + 1  # count
        cmd.Operands[1].phrase = (mcode >> (54 - 17)) & 0x1f
        cmd.Operands[1].type = o_displ
        addr = (mcode >> 3) & 0x7ffffff
        if addr & 0x4000000:  #negative number
           se = addr - 0x8000000
           cmd.Operands[1].value = se
        else:
           cmd.Operands[1].value = addr
        cmd.Operands[1].addr = cmd.Operands[1].value
        cmd.Operands[1].specval = ((mcode >> (54 - 22)) & 0x1f) + 1  # count
        cmd.itype = self.ifind(mnem)

    def dc_lds(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "LDS")
        cmd.Operands[0].dtyp = dt_byte
        cmd.Operands[1].dtyp = dt_byte

    def dc_ldt(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "LDT")
        cmd.Operands[0].dtyp = dt_3byte
        cmd.Operands[1].dtyp = dt_byte

    def dc_ldw(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "LDW")
        cmd.Operands[0].dtyp = dt_word
        cmd.Operands[1].dtyp = dt_word

    def dc_md(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "MDI")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "MD")
            cmd.Operands[2].specflag1 = 1
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "MDIS")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "MDS")
            cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_mdf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "MDF")

    def dc_mdfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "MDFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_mdm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "MDIM")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "MDM")
            cmd.Operands[2].specflag1 = 1
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "MDISM")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "MDSM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_mh(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        reg = (mcode >> (27 - 10)) & 0x1f
        cmd.Operands[0].reg = reg
        cmd.Operands[0].type = o_reg
        val = mcode & 0x1ffff
        cmd.Operands[1].value = val
        cmd.Operands[1].type = o_imm
        cmd.itype = self.ifind("MH")
        #support identifying creation of 3 byte addresses w/ ml/mh
        '''
        n = netnode(cmd.ea)
        idx_first = n.alt1st('z')
        if idx_first == (100 + reg):
           lo = n.altval(100 + reg, 'z')
           addr = (val << 10) | (lo & 0x3FF)
           n.altset(200 + reg, addr, 'z')
           p = netnode(cmd.ea - 3)
           p.altset(50, addr, 'z')
        '''
#           print "0x%x -> 0x%x" % (cmd.ea, addr)

    def dc_ml(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        reg = (mcode >> (27 - 10)) & 0x1f
        cmd.Operands[0].reg = reg
        cmd.Operands[0].type = o_reg
        cmd.Operands[0].dtyp = dt_3byte
        loval = mcode & 0x1ffff
        
        n1 = get_full_byte(cmd.ea + 3)
        n0 = get_full_byte(cmd.ea + 4)
        n = (n0 << 9) | n1
        upper5 = n >> (18 - 5)
        reg2 = (n >> (18-10)) & 0x1f
        if upper5 == 0x11 and reg2 == reg:
            n = (n << 9) | get_full_byte(cmd.ea + 5)
            cmd.size = 6
            val = n & 0x1ffff
            addr = (val << 10) | (loval & 0x3FF)
            cmd.Operands[1].value = addr
            cmd.Operands[1].addr = addr
            cmd.Operands[1].type = o_imm
            cmd.Operands[1].specflag3 = 1
            cmd.itype = self.ifind("MI")
        else:
            cmd.Operands[1].value = loval
            cmd.Operands[1].type = o_imm
            cmd.itype = self.ifind("ML")
        cmd.Operands[1].dtyp = dt_3byte

        '''
            #support identifying creation of 3 byte addresses w/ ml/mh
            n = netnode(cmd.ea + 3)
            n.altset(100 + reg, val, 'z')
            p = netnode(cmd.ea)
            if p.alt1st('z') == 50:
               addr = p.altval(50, 'z')
               cmd.size = 6
               cmd.Operands[1].value = addr
               cmd.Operands[1].type = o_imm
               cmd.itype = self.ifind("MI")
        '''

    def dc_ms(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27 - 10)) & 0x1f
        cmd.Operands[0].type = o_reg
        val = mcode & 0x1ffff
        if val & 0x10000:
           val |= 0x7ff0000
        cmd.Operands[1].value = val
        cmd.Operands[1].type = o_imm
        cmd.itype = self.ifind("MS")

    def dc_mu(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "MUI")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "MU")
            cmd.Operands[2].specflag1 = 1
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "MUIS")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "MUS")
            cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_muf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "MUF")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_mufm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "MUFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_mum(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        m = mcode & 6
        if m == 2:
            self.dc_gen_3_imm(cmd, mcode, "MUIM")
        elif m == 0:
            self.dc_gen_3(cmd, mcode, "MUM")
            cmd.Operands[2].specflag1 = 1
        elif m == 6:
            self.dc_gen_3_imm(cmd, mcode, "MUISM")
        elif m == 4:
            self.dc_gen_3(cmd, mcode, "MUSM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_ngf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "NGF")

    def dc_ngfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_2(cmd, mcode, "NGFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_or(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "ORI")
        else:
            self.dc_gen_3(cmd, mcode, "OR")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_orm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "ORM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_re(self, cmd, mcode):
        cmd.itype = self.ifind("RE")

    def dc_rf(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 1) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("RF")

    def dc_rl(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "RL")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rli(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "RLI")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rlim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "RLIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rlm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "RLM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rmp(self, cmd, mcode):    # and dc_smp
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27 - 12)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = (mcode >> (27 - 17)) & 0x1f
        cmd.Operands[1].type = o_reg
        if mcode & 0x200:
            cmd.itype = self.ifind("SMP")
            cmd.Operands[2].type = o_imm
            cmd.Operands[2].value = (mcode >> 7) & 0x3
            cmd.Operands[2].specflag2 = 1
        else:
            cmd.itype = self.ifind("RMP")

    def dc_rr(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "RR")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rri(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "RRI")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rrim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "RRIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_rrm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "RRM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sa(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SA")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sai(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SAI")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_saim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SAIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sam(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SAM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sb(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "SBI")
        else:
            self.dc_gen_3(cmd, mcode, "SB")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sbc(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "SBCI")
        else:
            self.dc_gen_3(cmd, mcode, "SBC")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sbcm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "SBCIM")
        else:
            self.dc_gen_3(cmd, mcode, "SBCM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sbf(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SBF")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sbfm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SBFM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.Operands[2].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sbm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "SBIM")
        else:
            self.dc_gen_3(cmd, mcode, "SBM")
            cmd.Operands[2].specflag1 = 1
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_ses(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27 - 17)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = (mcode >> (27 - 22)) & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.itype = self.ifind("SES")

    def dc_sew(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27 - 17)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = (mcode >> (27 - 22)) & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.itype = self.ifind("SEW")

    def dc_sf(self, cmd, mcode):
        cmd.Operands[0].reg = (mcode >> 1) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.itype = self.ifind("SF")

    def dc_sl(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SL")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sli(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SLI")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_slim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SLIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_slm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SLM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sr(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SR")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sri(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SRI")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_srim(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3_imm(cmd, mcode, "SRIM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_srm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "SRM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_sts(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "STS")
        cmd.Operands[0].dtyp = dt_byte
        cmd.Operands[1].dtyp = dt_byte

    def dc_stt(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "STT")
        cmd.Operands[0].dtyp = dt_3byte
        cmd.Operands[1].dtyp = dt_3byte

    def dc_stw(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_ld(cmd, mcode, "STW")
        cmd.Operands[0].dtyp = dt_word
        cmd.Operands[1].dtyp = dt_word

    def dc_wt(self, cmd, mcode):
        cmd.itype = self.ifind("WT")

    def dc_xr(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        if mcode & 2:
            self.dc_gen_3_imm(cmd, mcode, "XRI")
        else:
            self.dc_gen_3(cmd, mcode, "XR")
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_xrm(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        self.dc_gen_3(cmd, mcode, "XRM")
        cmd.Operands[0].specflag1 = 1
        cmd.Operands[1].specflag1 = 1
        cmd.auxpref = 3 * (mcode & 1)   #UF

    def dc_zes(self, cmd, mcode):
        mcode = append_next_byte(mcode, cmd)
        cmd.Operands[0].reg = (mcode >> (27 - 17)) & 0x1f
        cmd.Operands[0].type = o_reg
        cmd.Operands[1].reg = (mcode >> (27 - 22)) & 0x1f
        cmd.Operands[1].type = o_reg
        cmd.itype = self.ifind("ZES")

    handlers5 = {
        0x11 : dc_mh,
        0x12 : dc_ml,
        0x13 : dc_ms
    }

    handlers6 = {
        0x30 : dc_b,
        0x32 : dc_br,
        0x35 : dc_c,
        0x37 : dc_cr
    }

    handlers7 = {
        0 : dc_ad,
        0x20 : dc_adc,
        0x22 : dc_adcm,
        1 : dc_adf,
        3 : dc_adfm,
        2 : dc_adm,
        0x14 : dc_an,
        0x16 : dc_anm,
        0x34 : dc_dmt,
        0xc : dc_dv,
        0xd : dc_dvf,
        0xf : dc_dvfm,
        0xe : dc_dvm,
        0x54 : dc_lds,
        0x56 : dc_ldt,
        0x55 : dc_ldw,
        0x10 : dc_md,
        0x11 : dc_mdf,
        0x13 : dc_mdfm,
        0x12 : dc_mdm,
        8 : dc_mu,
        9 : dc_muf,
        0xb : dc_mufm,
        0xa : dc_mum,
        0x18 : dc_or,
        0x1a : dc_orm,
        0x30 : dc_rl,
        0x40 : dc_rli,
        0x42 : dc_rlim,
        0x32 : dc_rlm,
        0x52 : dc_rmp,
        0x31 : dc_rr,
        0x41 : dc_rri,
        0x43 : dc_rrim,
        0x33 : dc_rrm,
        0x2d : dc_sa,
        0x3d : dc_sai,
        0x3f : dc_saim,
        0x2f : dc_sam,
        4 : dc_sb,
        0x24 : dc_sbc,
        0x26 : dc_sbcm,
        5 : dc_sbf,
        7 : dc_sbfm,
        6 : dc_sbm,
        0x28 : dc_sl,
        0x38 : dc_sli,
        0x3a : dc_slim,
        0x2a : dc_slm,
        0x29 : dc_sr,
        0x39 : dc_sri,
        0x3b : dc_srim,
        0x2b : dc_srm,
        0x58 : dc_sts,
        0x5a : dc_stt,
        0x59 : dc_stw,
        0x1c : dc_xr,
        0x1e : dc_xrm
    }

    handlers8 = {
        0xb8 : dc_cm,
        0xba : dc_cmf,
        0xbe : dc_cmfm,
        0xb9 : dc_cmi,
        0xbd : dc_cmim,
        0xbc : dc_cmm
    }

    handlers9 = {
        0x14c : dc_bf,    #dc_ng dc_nt dc_rnd
        0x14e : dc_bfm,  #dc_ngm dc_ntm dc_rndm
        0x1c4 : dc_bra,
        0x1c0 : dc_brr,
        0x1cc : dc_caa,
        0x1c8 : dc_car,
        0x145 : dc_fti,
        0x147 : dc_ftim,
        0x144 : dc_itf,
        0x146 : dc_itfm,
        0x14d : dc_ngf,
        0x14f : dc_ngfm
    }

    handlers12 = {
        0xa05 : dc_di,
        0xa04 : dc_ei,
        0xa0c : dc_rf,
        0xa07 : dc_ses,
        0xa08 : dc_sew,
        0xa0b : dc_sf,
        0xa09 : dc_zes
    }

    handlers18 = {
        0x3ffff : dc_dbrk,
        0x280C0 : dc_ht,
        0x28040 : dc_ir,
        0x28000 : dc_re,
        0x28080 : dc_wt
    }

    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """

        b1 = my_ua_next_byte(cmd)
        b0 = my_ua_next_byte(cmd)
        mcode = (b0 << 9) + b1

#        print "mcode = 0x%x, b1 = 0x%x, b0 = 0x%x" % (mcode, b1, b0)

        top12 = mcode >> 6
        top9 = mcode >> 9
        top8 = mcode >> 10
        top7 = mcode >> 11
        top6 = mcode >> 12
        top5 = mcode >> 13

        try:
           if mcode in clemency_processor_t.handlers18:
               clemency_processor_t.handlers18[mcode](self, self.cmd, mcode)
           elif top12 in clemency_processor_t.handlers12:
               clemency_processor_t.handlers12[top12](self, self.cmd, mcode)
           elif top9 in clemency_processor_t.handlers9:
               clemency_processor_t.handlers9[top9](self, self.cmd, mcode)
           elif top8 in clemency_processor_t.handlers8:
               clemency_processor_t.handlers8[top8](self, self.cmd, mcode)
           elif top7 in clemency_processor_t.handlers7:
               clemency_processor_t.handlers7[top7](self, self.cmd, mcode)
           elif top6 in clemency_processor_t.handlers6:
               clemency_processor_t.handlers6[top6](self, self.cmd, mcode)
           elif top5 in clemency_processor_t.handlers5:
               clemency_processor_t.handlers5[top5](self, self.cmd, mcode)
           else:
               print "unknown opcode at address 0x%x: 0x%x" % (cmd.ea, mcode)
               return 0
        except BadMnemonic, e:
           print "bad mnemonic: %s" % e.mnem
           return 0

        # Return decoded instruction size or zero
        return self.cmd.size

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return clemency_processor_t()
