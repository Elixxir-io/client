// Code generated by protoc-gen-go. DO NOT EDIT.
// source: types.proto

/*
Package parse is a generated protocol buffer package.

It is generated from these files:
	types.proto

It has these top-level messages:
	TextMessage
	ChannelMessage
	PaymentInvoice
*/
package parse

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Type int32

const (
	Type_NO_TYPE         Type = 0
	Type_TEXT_MESSAGE    Type = 1
	Type_CHANNEL_MESSAGE Type = 2
	// We currently parse these types without using proto buffers
	// We use the types, but don't look for proto buffer definitions
	Type_UDB_PUSH_KEY          Type = 10
	Type_UDB_PUSH_KEY_RESPONSE Type = 11
	Type_UDB_GET_KEY           Type = 12
	Type_UDB_GET_KEY_RESPONSE  Type = 13
	Type_UDB_REGISTER          Type = 14
	Type_UDB_REGISTER_RESPONSE Type = 15
	Type_UDB_SEARCH            Type = 16
	Type_UDB_SEARCH_RESPONSE   Type = 17
	// Same with the payment bot types
	Type_PAYMENT Type = 20
	// Payment invoice uses a proto buffer because it might make things easier
	Type_PAYMENT_INVOICE Type = 21
)

var Type_name = map[int32]string{
	0:  "NO_TYPE",
	1:  "TEXT_MESSAGE",
	2:  "CHANNEL_MESSAGE",
	10: "UDB_PUSH_KEY",
	11: "UDB_PUSH_KEY_RESPONSE",
	12: "UDB_GET_KEY",
	13: "UDB_GET_KEY_RESPONSE",
	14: "UDB_REGISTER",
	15: "UDB_REGISTER_RESPONSE",
	16: "UDB_SEARCH",
	17: "UDB_SEARCH_RESPONSE",
	20: "PAYMENT",
	21: "PAYMENT_INVOICE",
}
var Type_value = map[string]int32{
	"NO_TYPE":               0,
	"TEXT_MESSAGE":          1,
	"CHANNEL_MESSAGE":       2,
	"UDB_PUSH_KEY":          10,
	"UDB_PUSH_KEY_RESPONSE": 11,
	"UDB_GET_KEY":           12,
	"UDB_GET_KEY_RESPONSE":  13,
	"UDB_REGISTER":          14,
	"UDB_REGISTER_RESPONSE": 15,
	"UDB_SEARCH":            16,
	"UDB_SEARCH_RESPONSE":   17,
	"PAYMENT":               20,
	"PAYMENT_INVOICE":       21,
}

func (x Type) String() string {
	return proto.EnumName(Type_name, int32(x))
}
func (Type) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type TextMessage struct {
	Color   int32  `protobuf:"zigzag32,2,opt,name=color" json:"color,omitempty"`
	Message string `protobuf:"bytes,3,opt,name=message" json:"message,omitempty"`
	Time    int64  `protobuf:"varint,4,opt,name=time" json:"time,omitempty"`
}

func (m *TextMessage) Reset()                    { *m = TextMessage{} }
func (m *TextMessage) String() string            { return proto.CompactTextString(m) }
func (*TextMessage) ProtoMessage()               {}
func (*TextMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *TextMessage) GetColor() int32 {
	if m != nil {
		return m.Color
	}
	return 0
}

func (m *TextMessage) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *TextMessage) GetTime() int64 {
	if m != nil {
		return m.Time
	}
	return 0
}

type ChannelMessage struct {
	SpeakerID []byte `protobuf:"bytes,3,opt,name=speakerID,proto3" json:"speakerID,omitempty"`
	Message   []byte `protobuf:"bytes,4,opt,name=message,proto3" json:"message,omitempty"`
}

func (m *ChannelMessage) Reset()                    { *m = ChannelMessage{} }
func (m *ChannelMessage) String() string            { return proto.CompactTextString(m) }
func (*ChannelMessage) ProtoMessage()               {}
func (*ChannelMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *ChannelMessage) GetSpeakerID() []byte {
	if m != nil {
		return m.SpeakerID
	}
	return nil
}

func (m *ChannelMessage) GetMessage() []byte {
	if m != nil {
		return m.Message
	}
	return nil
}

// Payment message types
type PaymentInvoice struct {
	Time        int64  `protobuf:"varint,1,opt,name=time" json:"time,omitempty"`
	CreatedCoin []byte `protobuf:"bytes,2,opt,name=createdCoin,proto3" json:"createdCoin,omitempty"`
	Memo        string `protobuf:"bytes,3,opt,name=memo" json:"memo,omitempty"`
}

func (m *PaymentInvoice) Reset()                    { *m = PaymentInvoice{} }
func (m *PaymentInvoice) String() string            { return proto.CompactTextString(m) }
func (*PaymentInvoice) ProtoMessage()               {}
func (*PaymentInvoice) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PaymentInvoice) GetTime() int64 {
	if m != nil {
		return m.Time
	}
	return 0
}

func (m *PaymentInvoice) GetCreatedCoin() []byte {
	if m != nil {
		return m.CreatedCoin
	}
	return nil
}

func (m *PaymentInvoice) GetMemo() string {
	if m != nil {
		return m.Memo
	}
	return ""
}

func init() {
	proto.RegisterType((*TextMessage)(nil), "parse.TextMessage")
	proto.RegisterType((*ChannelMessage)(nil), "parse.ChannelMessage")
	proto.RegisterType((*PaymentInvoice)(nil), "parse.PaymentInvoice")
	proto.RegisterEnum("parse.Type", Type_name, Type_value)
}

func init() { proto.RegisterFile("types.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 359 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x92, 0xcf, 0x4e, 0xc2, 0x40,
	0x10, 0xc6, 0x2d, 0x14, 0x09, 0xd3, 0x5a, 0x96, 0x05, 0x62, 0x4d, 0x3c, 0x34, 0x9c, 0x88, 0x07,
	0x2f, 0x3e, 0x41, 0x29, 0x1b, 0xda, 0x28, 0xa5, 0x6e, 0x17, 0x23, 0x5c, 0x9a, 0x8a, 0x1b, 0x25,
	0xd2, 0x3f, 0x69, 0x1b, 0x23, 0xaf, 0xe0, 0x53, 0x9b, 0x16, 0xea, 0xf6, 0xb6, 0xdf, 0x37, 0xbf,
	0xfd, 0x66, 0x26, 0x19, 0x50, 0x8a, 0x63, 0xca, 0xf3, 0xfb, 0x34, 0x4b, 0x8a, 0x04, 0x77, 0xd2,
	0x30, 0xcb, 0xf9, 0xe4, 0x19, 0x14, 0xc6, 0x7f, 0x8a, 0x25, 0xcf, 0xf3, 0xf0, 0x83, 0xe3, 0x11,
	0x74, 0x76, 0xc9, 0x21, 0xc9, 0xf4, 0x96, 0x21, 0x4d, 0x07, 0xf4, 0x24, 0xb0, 0x0e, 0xdd, 0xe8,
	0x04, 0xe8, 0x6d, 0x43, 0x9a, 0xf6, 0x68, 0x2d, 0x31, 0x06, 0xb9, 0xd8, 0x47, 0x5c, 0x97, 0x0d,
	0x69, 0xda, 0xa6, 0xd5, 0x7b, 0x62, 0x83, 0x66, 0x7d, 0x86, 0x71, 0xcc, 0x0f, 0x75, 0xea, 0x2d,
	0xf4, 0xf2, 0x94, 0x87, 0x5f, 0x3c, 0x73, 0xe6, 0x55, 0x82, 0x4a, 0x85, 0xd1, 0x4c, 0x97, 0xab,
	0x5a, 0x2d, 0x27, 0x5b, 0xd0, 0xbc, 0xf0, 0x18, 0xf1, 0xb8, 0x70, 0xe2, 0xef, 0x64, 0xbf, 0x13,
	0xfd, 0x24, 0xd1, 0x0f, 0x1b, 0xa0, 0xec, 0x32, 0x1e, 0x16, 0xfc, 0xdd, 0x4a, 0xf6, 0x71, 0x35,
	0xb9, 0x4a, 0x9b, 0x56, 0xf9, 0x2b, 0xe2, 0x51, 0x72, 0x1e, 0xbe, 0x7a, 0xdf, 0xfd, 0xb6, 0x40,
	0x66, 0xc7, 0x94, 0x63, 0x05, 0xba, 0xee, 0x2a, 0x60, 0x1b, 0x8f, 0xa0, 0x0b, 0x8c, 0x40, 0x65,
	0xe4, 0x95, 0x05, 0x4b, 0xe2, 0xfb, 0xe6, 0x82, 0x20, 0x09, 0x0f, 0xa1, 0x6f, 0xd9, 0xa6, 0xeb,
	0x92, 0xa7, 0x7f, 0xb3, 0x55, 0x62, 0xeb, 0xf9, 0x2c, 0xf0, 0xd6, 0xbe, 0x1d, 0x3c, 0x92, 0x0d,
	0x02, 0x7c, 0x03, 0xe3, 0xa6, 0x13, 0x50, 0xe2, 0x7b, 0x2b, 0xd7, 0x27, 0x48, 0xc1, 0x7d, 0x50,
	0xca, 0xd2, 0x82, 0xb0, 0x8a, 0x55, 0xb1, 0x0e, 0xa3, 0x86, 0x21, 0xd0, 0xab, 0x3a, 0x97, 0x92,
	0x85, 0xe3, 0x33, 0x42, 0x91, 0x56, 0xe7, 0xd6, 0x8e, 0x80, 0xfb, 0x58, 0x03, 0x28, 0x4b, 0x3e,
	0x31, 0xa9, 0x65, 0x23, 0x84, 0xaf, 0x61, 0x28, 0xb4, 0x00, 0x07, 0xe5, 0x86, 0x9e, 0xb9, 0x59,
	0x12, 0x97, 0xa1, 0x51, 0xb9, 0xcf, 0x59, 0x04, 0x8e, 0xfb, 0xb2, 0x72, 0x2c, 0x82, 0xc6, 0xb3,
	0xee, 0xf6, 0x74, 0x0e, 0x6f, 0x97, 0xd5, 0x71, 0x3c, 0xfc, 0x05, 0x00, 0x00, 0xff, 0xff, 0x4a,
	0x78, 0xef, 0xec, 0x2b, 0x02, 0x00, 0x00,
}
