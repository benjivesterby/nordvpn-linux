# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: account.proto
# Protobuf Python Version: 5.28.1
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    28,
    1,
    '',
    'account.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\raccount.proto\x12\x02pb\x1a\x0c\x63ommon.proto\"J\n\x13\x44\x65\x64idcatedIPService\x12\x12\n\nserver_ids\x18\x01 \x03(\x03\x12\x1f\n\x17\x64\x65\x64icated_ip_expires_at\x18\x02 \x01(\t\"\xf1\x01\n\x0f\x41\x63\x63ountResponse\x12\x0c\n\x04type\x18\x01 \x01(\x03\x12\x10\n\x08username\x18\x02 \x01(\t\x12\r\n\x05\x65mail\x18\x03 \x01(\t\x12\x12\n\nexpires_at\x18\x04 \x01(\t\x12\x1b\n\x13\x64\x65\x64icated_ip_status\x18\x05 \x01(\x03\x12$\n\x1clast_dedicated_ip_expires_at\x18\x06 \x01(\t\x12\x36\n\x15\x64\x65\x64icated_ip_services\x18\x07 \x03(\x0b\x32\x17.pb.DedidcatedIPService\x12 \n\nmfa_status\x18\x08 \x01(\x0e\x32\x0c.pb.TriState\"\x1e\n\x0e\x41\x63\x63ountRequest\x12\x0c\n\x04\x66ull\x18\x01 \x01(\x08\x42\x31Z/github.com/NordSecurity/nordvpn-linux/daemon/pbb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'account_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'Z/github.com/NordSecurity/nordvpn-linux/daemon/pb'
  _globals['_DEDIDCATEDIPSERVICE']._serialized_start=35
  _globals['_DEDIDCATEDIPSERVICE']._serialized_end=109
  _globals['_ACCOUNTRESPONSE']._serialized_start=112
  _globals['_ACCOUNTRESPONSE']._serialized_end=353
  _globals['_ACCOUNTREQUEST']._serialized_start=355
  _globals['_ACCOUNTREQUEST']._serialized_end=385
# @@protoc_insertion_point(module_scope)
