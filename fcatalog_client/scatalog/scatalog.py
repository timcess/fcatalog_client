from idaapi import *
from idc import *
from idautils import *
import networkx as nx

import collections
import struct

#-*-coding:utf-8-*-

#TODO: Think about Unions and Enums
# Dumps one structure. It would be impossible to recover the structure by this dump
# if the structure included a pointer to another structure or another structure as a member.
# The function also returns names of all structure members that must exist before recovering
# the structure.
#
# It seems that IDA Python API doesn't allow to get Struct Id of a structure pointer member.
# So all stuff with structure pointers should be done manually.
#
# Dump format:
# StructName,0,member_count(4b),member_name,0,offset(4b),type(4b),is_structure(1b),[name_of_structure if is_structure == 1,0],size_in_bytes(4b),
def dump_structure(sid):
    require = []
    dump = ""
    dump += GetStrucName(sid)
    dump += "\0"
    dump += struct.pack("<I", GetMemberQty(sid))
    for mem_off, mem_name, mem_size in StructMembers(sid):
        dump += mem_name
        dump += "\0"
        dump += struct.pack("<I", mem_off)
        mem_type = GetMemberFlag(sid, mem_off)

        dump += struct.pack("<I", mem_type)

        if isStruct(mem_type):
            mem_sid = GetMemberStrId(sid, mem_off)
            dump += GetStrucName(mem_sid)
            dump += "\0"
            require.append(GetStrucName(mem_sid))

        dump += struct.pack("<I", mem_size)

    return dump, require

def get_4b_int(data):
    assert len(data) >= 4
    res = struct.unpack("<I", data[:4])[0]
    data = data[4:]
    return int(res), data

def get_str(data):
    i = data.find("\x00")
    res = data[:i]
    data = data[i+1:]
    return res, data

def satisfy(struct_names, require):
    for name in require:
        if struct_names[name] == 0:
            return False
    return True


class Struct:
    def __init__(self, ida_struct):
        self.name = ida_struct[2]
        self.number = ida_struct[0]
        self.sid = ida_struct[1]
        self.dump = None

def all_structs():
    for s in Structs():
        yield Struct(s)

class StructDumper:
    def __init__(self):
        self._G = nx.DiGraph()
        for s in all_structs():
            self._G.add_node(s.name)
            self._G[s.name]['struct_object'] = s

        for s_name in self._G.nodes():
            s = self._G[s_name]['struct_object']
            dump, require = dump_structure(s.sid)
            s.dump = dump
            # Edge from struct A to struct B if
            # A is member of B
            for s_req in require:
                self._G.add_edge(s_req, s_name)

    def all_struct_dumps(self):
        for s_name in self._G.nodes():
            dump = self.dump_struct_by_name(s_name)
            yield s_name, dump

    def dump_struct_by_name(self, s_name):
            # subgraph_nodes are vertices that required by
            # current structure s_name
            subgraph_nodes = nx.ancestors(self._G, s_name)
            subgraph_nodes.add(s_name)
            if subgraph_nodes is not None:
                H = self._G.subgraph(subgraph_nodes)
                order = nx.topological_sort(H)

                complex_struct_dump = ""
                for ss_name in order:
                    struct_dump = self._G[ss_name]['struct_object'].dump
                    complex_struct_dump += struct.pack("<I", len(struct_dump))
                    complex_struct_dump += struct_dump

                return complex_struct_dump

# Sometimes idc functions in python returns 4294967295
# instead of -1
def is_error(ret):
    return (ret & 0xffffffff) == (-1 & 0xffffffff)


def get_err_msg(code):
    msg = "Unexpected error"
    if code == -1:
        msg = "already has member with this name (bad name)"
    if code == -2:
        msg = "already has member at this offset"
    if code == -3:
        msg = "bad number of bytes or bad sizeof(type)"
    if code == -4:
        msg = "bad typeid parameter"
    if code == -5:
        msg = "bad struct id (the 1st argument)"
    if code == -6:
        msg = "unions can't have variable sized members"
    if code == -7:
        msg = "variable sized member should be the last member in the structure"
    if code == -8:
        msg = "recursive structure nesting is forbidden"
    if code == -9:
        msg = "Structure doesn't exist and error while adding structure. \
               Check structure name."
    if code == -10:
        msg = "Member of type structure doesn't exist"
    return msg


# Creates structure by simple dump, got by dump_structure()
def recover_simple_structure(data):
    struct_name, data = get_str(data)
    sid = AddStruc(-1, struct_name)

    if is_error(sid):
        # May be such struct already exists?
        sid = GetStrucIdByName(struct_name)
        if is_error(sid):
            #Something strange happend, return
            return -9
        else:
            #We already have such structure, leave it
            return 0

    debug_msg = ""
    debug_msg += "Struct Name: "+str(struct_name)+"\n"
    members_count, data = get_4b_int(data)
    debug_msg += "Members_count: "+str(members_count)+"\n"
    for i in xrange(members_count):
        member_name, data = get_str(data)
        debug_msg += " "*4+"Member Name: "+str(member_name)+"\n"

        member_offset, data = get_4b_int(data)
        debug_msg += " "*4+"Member Offset: "+str(member_offset)+"\n"

        member_type, data = get_4b_int(data)
        debug_msg += " "*4+"Member Type: "+str(member_type)+"\n"

        if isStruct(member_type):
            member_struct_name, data = get_str(data)
            # This struct MUST exists
            typeid = GetStrucIdByName(member_struct_name)
            if is_error(sid):
                return -10
        else:
            typeid = -1

        member_size, data = get_4b_int(data)
        debug_msg += " "*4+"Member Size: "+str(member_size)+"\n"

        ret = idc.AddStrucMember(sid, member_name, member_offset, member_type, typeid, member_size)
        if ret != 0:
            print "Error Code: "+str(ret)
            print debug_msg
            return ret

    return 0

# [Len_of_next_dump(4b),Dump]{1,}
def create_structure(dump):
    rest_data = dump
    while len(rest_data) > 0:
        dump_len = struct.unpack("<I", rest_data[:4])[0]
        ret = recover_simple_structure(rest_data[4:4+dump_len])
        if ret != 0:
            return ret
        rest_data = rest_data[4+dump_len:]
    return 0
