#!/usr/bin/env python3
"""Bounded read-only observation of the SteamInternal_ContextInit guest argument.

The documented Steamworks generated accessor uses a 3-pointer array:
callback, generation/counter, cached interface pointer. This inspector
*only reads* the authentic mapped guest memory at a verified import call.
It does not call the callback, create an interface, authenticate or
claim that this is the installed SDK layout without checking values.
"""
from __future__ import annotations
import struct
from unicorn.x86_const import UC_X86_REG_RCX

def inspect_context_init_data(guest, image_base: int, image_end: int) -> dict:
    argument = guest.reg_read(UC_X86_REG_RCX)
    result = {
        "call": "steam_api64.dll!SteamInternal_ContextInit",
        "guest_argument_in_original_image": False,
        "original_image_argument_rva": None,
        "mapped_data_read": False,
        "initializer_callback_in_original_image": False,
        "initializer_callback_rva": None,
        "counter_zero": None,
        "cached_interface_pointer_zero": None,
        "layout_is_tentative": True,
        "interfaces_created_or_returned": False,
        "steam_client_authenticated": False,
    }
    if (not isinstance(argument,int) or
        not isinstance(image_base,int) or not isinstance(image_end,int) or
        image_base<0 or image_end<image_base+24 or
        argument<image_base or argument>image_end-24 or argument%8):
        return result
    result["guest_argument_in_original_image"]=True
    result["original_image_argument_rva"]=hex(argument-image_base)
    try:
        raw=bytes(guest.mem_read(argument,24))
        if len(raw)!=24:
            return result
        callback,counter,cached=struct.unpack("<QQQ",raw)
    except Exception:
        return result
    result["mapped_data_read"]=True
    result["counter_zero"]=counter==0
    result["cached_interface_pointer_zero"]=cached==0
    if image_base<=callback<image_end:
        result["initializer_callback_in_original_image"]=True
        result["initializer_callback_rva"]=hex(callback-image_base)
    return result
