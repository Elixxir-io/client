////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        (unknown)
// source: messages.proto

package channels

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

// ChannelMessage is transmitted by the channel. Effectively it is
// a command for the channel sent by a user with admin access of the channel.
type ChannelMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Lease is the length that this channel message will take effect.
	Lease int64 `protobuf:"varint,1,opt,name=Lease,json=lease,proto3" json:"Lease,omitempty"`
	// The round this message was sent on
	RoundID uint64 `protobuf:"varint,2,opt,name=RoundID,json=roundID,proto3" json:"RoundID,omitempty"`
	// The type the below payload is. This may be some form of channel command,
	// such as BAN<username1>.
	PayloadType uint32 `protobuf:"varint,3,opt,name=PayloadType,json=payloadType,proto3" json:"PayloadType,omitempty"`
	// Payload is the actual message payload. It will be processed differently based
	// on the PayloadType
	Payload []byte `protobuf:"bytes,4,opt,name=Payload,json=payload,proto3" json:"Payload,omitempty"`
}

func (x *ChannelMessage) Reset() {
	*x = ChannelMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ChannelMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ChannelMessage) ProtoMessage() {}

func (x *ChannelMessage) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ChannelMessage.ProtoReflect.Descriptor instead.
func (*ChannelMessage) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{0}
}

func (x *ChannelMessage) GetLease() int64 {
	if x != nil {
		return x.Lease
	}
	return 0
}

func (x *ChannelMessage) GetRoundID() uint64 {
	if x != nil {
		return x.RoundID
	}
	return 0
}

func (x *ChannelMessage) GetPayloadType() uint32 {
	if x != nil {
		return x.PayloadType
	}
	return 0
}

func (x *ChannelMessage) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

// UserMessage is a message sent by a user who is a member within the channel.
type UserMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Message contains the contents of the message. This is typically what
	// the end-user has submitted to the channel. This is a serialization of the
	// ChannelMessage.
	Message []byte `protobuf:"bytes,1,opt,name=Message,json=message,proto3" json:"Message,omitempty"`
	// ValidationSignature is the signature validating this user owns
	// their username and may send messages to the channel under this username.
	// This signature is provided by UD and may be validated by all members of
	// the channel.
	// ValidationSignature = Sig(UD_ECCPrivKey,Username|ECCPublicKey|UsernameLease)
	ValidationSignature []byte `protobuf:"bytes,2,opt,name=ValidationSignature,json=validationSignature,proto3" json:"ValidationSignature,omitempty"`
	// Signature is the signature proving this message has been
	// sent by the owner of this user's public key.
	// Signature = Sig(User_ECCPublicKey,Message)
	Signature []byte `protobuf:"bytes,3,opt,name=Signature,json=signature,proto3" json:"Signature,omitempty"`
	// Username is the username the user has registered with the channel and
	// with UD.
	Username string `protobuf:"bytes,4,opt,name=Username,json=username,proto3" json:"Username,omitempty"`
	// ECCPublicKey is the user's EC Public key. This is provided by the network.
	ECCPublicKey []byte `protobuf:"bytes,5,opt,name=ECCPublicKey,json=eCCPublicKey,proto3" json:"ECCPublicKey,omitempty"`
	// UsernameLease is the lease that has been provided to the username.
	// This value is provide by UD.
	UsernameLease int64 `protobuf:"varint,6,opt,name=UsernameLease,json=usernameLease,proto3" json:"UsernameLease,omitempty"`
}

func (x *UserMessage) Reset() {
	*x = UserMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_messages_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserMessage) ProtoMessage() {}

func (x *UserMessage) ProtoReflect() protoreflect.Message {
	mi := &file_messages_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserMessage.ProtoReflect.Descriptor instead.
func (*UserMessage) Descriptor() ([]byte, []int) {
	return file_messages_proto_rawDescGZIP(), []int{1}
}

func (x *UserMessage) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

func (x *UserMessage) GetValidationSignature() []byte {
	if x != nil {
		return x.ValidationSignature
	}
	return nil
}

func (x *UserMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *UserMessage) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *UserMessage) GetECCPublicKey() []byte {
	if x != nil {
		return x.ECCPublicKey
	}
	return nil
}

func (x *UserMessage) GetUsernameLease() int64 {
	if x != nil {
		return x.UsernameLease
	}
	return 0
}

var File_messages_proto protoreflect.FileDescriptor

var file_messages_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x05, 0x70, 0x61, 0x72, 0x73, 0x65, 0x22, 0x7c, 0x0a, 0x0e, 0x43, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x4c, 0x65, 0x61,
	0x73, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x07, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x49, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x50, 0x61, 0x79,
	0x6c, 0x6f, 0x61, 0x64, 0x54, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x54, 0x79, 0x70, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x50,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xdd, 0x01, 0x0a, 0x0b, 0x55, 0x73, 0x65, 0x72, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x30, 0x0a, 0x13, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x13, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x12, 0x1c, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12,
	0x1a, 0x0a, 0x08, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x45,
	0x43, 0x43, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0c, 0x65, 0x43, 0x43, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x12,
	0x24, 0x0a, 0x0d, 0x55, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x4c, 0x65, 0x61, 0x73, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65,
	0x4c, 0x65, 0x61, 0x73, 0x65, 0x42, 0x0b, 0x5a, 0x09, 0x2f, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65,
	0x6c, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_messages_proto_rawDescOnce sync.Once
	file_messages_proto_rawDescData = file_messages_proto_rawDesc
)

func file_messages_proto_rawDescGZIP() []byte {
	file_messages_proto_rawDescOnce.Do(func() {
		file_messages_proto_rawDescData = protoimpl.X.CompressGZIP(file_messages_proto_rawDescData)
	})
	return file_messages_proto_rawDescData
}

var file_messages_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_messages_proto_goTypes = []interface{}{
	(*ChannelMessage)(nil), // 0: parse.ChannelMessage
	(*UserMessage)(nil),    // 1: parse.UserMessage
}
var file_messages_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_messages_proto_init() }
func file_messages_proto_init() {
	if File_messages_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_messages_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ChannelMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_messages_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_messages_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_messages_proto_goTypes,
		DependencyIndexes: file_messages_proto_depIdxs,
		MessageInfos:      file_messages_proto_msgTypes,
	}.Build()
	File_messages_proto = out.File
	file_messages_proto_rawDesc = nil
	file_messages_proto_goTypes = nil
	file_messages_proto_depIdxs = nil
}
