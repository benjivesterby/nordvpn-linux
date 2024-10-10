// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v3.21.6
// source: token.proto

package pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TokenInfoResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type               int64  `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Token              string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
	ExpiresAt          string `protobuf:"bytes,3,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	TrustedPassToken   string `protobuf:"bytes,4,opt,name=trusted_pass_token,json=trustedPassToken,proto3" json:"trusted_pass_token,omitempty"`
	TrustedPassOwnerId string `protobuf:"bytes,5,opt,name=trusted_pass_owner_id,json=trustedPassOwnerId,proto3" json:"trusted_pass_owner_id,omitempty"`
}

func (x *TokenInfoResponse) Reset() {
	*x = TokenInfoResponse{}
	mi := &file_token_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TokenInfoResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TokenInfoResponse) ProtoMessage() {}

func (x *TokenInfoResponse) ProtoReflect() protoreflect.Message {
	mi := &file_token_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TokenInfoResponse.ProtoReflect.Descriptor instead.
func (*TokenInfoResponse) Descriptor() ([]byte, []int) {
	return file_token_proto_rawDescGZIP(), []int{0}
}

func (x *TokenInfoResponse) GetType() int64 {
	if x != nil {
		return x.Type
	}
	return 0
}

func (x *TokenInfoResponse) GetToken() string {
	if x != nil {
		return x.Token
	}
	return ""
}

func (x *TokenInfoResponse) GetExpiresAt() string {
	if x != nil {
		return x.ExpiresAt
	}
	return ""
}

func (x *TokenInfoResponse) GetTrustedPassToken() string {
	if x != nil {
		return x.TrustedPassToken
	}
	return ""
}

func (x *TokenInfoResponse) GetTrustedPassOwnerId() string {
	if x != nil {
		return x.TrustedPassOwnerId
	}
	return ""
}

var File_token_proto protoreflect.FileDescriptor

var file_token_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x02, 0x70,
	0x62, 0x22, 0xbd, 0x01, 0x0a, 0x11, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x49, 0x6e, 0x66, 0x6f, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x74,
	0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x74, 0x6f, 0x6b, 0x65,
	0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x41, 0x74,
	0x12, 0x2c, 0x0a, 0x12, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x73, 0x73,
	0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x74, 0x72,
	0x75, 0x73, 0x74, 0x65, 0x64, 0x50, 0x61, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x31,
	0x0a, 0x15, 0x74, 0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x5f, 0x6f,
	0x77, 0x6e, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x74,
	0x72, 0x75, 0x73, 0x74, 0x65, 0x64, 0x50, 0x61, 0x73, 0x73, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x49,
	0x64, 0x42, 0x31, 0x5a, 0x2f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x4e, 0x6f, 0x72, 0x64, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2f, 0x6e, 0x6f, 0x72,
	0x64, 0x76, 0x70, 0x6e, 0x2d, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x2f, 0x64, 0x61, 0x65, 0x6d, 0x6f,
	0x6e, 0x2f, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_token_proto_rawDescOnce sync.Once
	file_token_proto_rawDescData = file_token_proto_rawDesc
)

func file_token_proto_rawDescGZIP() []byte {
	file_token_proto_rawDescOnce.Do(func() {
		file_token_proto_rawDescData = protoimpl.X.CompressGZIP(file_token_proto_rawDescData)
	})
	return file_token_proto_rawDescData
}

var file_token_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_token_proto_goTypes = []any{
	(*TokenInfoResponse)(nil), // 0: pb.TokenInfoResponse
}
var file_token_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_token_proto_init() }
func file_token_proto_init() {
	if File_token_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_token_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_token_proto_goTypes,
		DependencyIndexes: file_token_proto_depIdxs,
		MessageInfos:      file_token_proto_msgTypes,
	}.Build()
	File_token_proto = out.File
	file_token_proto_rawDesc = nil
	file_token_proto_goTypes = nil
	file_token_proto_depIdxs = nil
}
