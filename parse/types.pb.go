// Code generated by protoc-gen-go. DO NOT EDIT.
// source: types.proto

/*
Package parse is a generated protocol buffer package.

It is generated from these files:
	types.proto

It has these top-level messages:
	TextMessage
	ChannelMessage
	PaymentResponse
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
	Type_PAYMENT          Type = 20
	Type_PAYMENT_RESPONSE Type = 21
	// Payment invoice uses a proto buffer because it might make things easier
	Type_PAYMENT_INVOICE Type = 22
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
	21: "PAYMENT_RESPONSE",
	22: "PAYMENT_INVOICE",
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
	"PAYMENT_RESPONSE":      21,
	"PAYMENT_INVOICE":       22,
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
type PaymentResponse struct {
	Success  bool   `protobuf:"varint,1,opt,name=success" json:"success,omitempty"`
	Response string `protobuf:"bytes,2,opt,name=response" json:"response,omitempty"`
	// TODO Is it correct to use the whole hash?
	ID string `protobuf:"bytes,3,opt,name=ID" json:"ID,omitempty"`
}

func (m *PaymentResponse) Reset()                    { *m = PaymentResponse{} }
func (m *PaymentResponse) String() string            { return proto.CompactTextString(m) }
func (*PaymentResponse) ProtoMessage()               {}
func (*PaymentResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *PaymentResponse) GetSuccess() bool {
	if m != nil {
		return m.Success
	}
	return false
}

func (m *PaymentResponse) GetResponse() string {
	if m != nil {
		return m.Response
	}
	return ""
}

func (m *PaymentResponse) GetID() string {
	if m != nil {
		return m.ID
	}
	return ""
}

type PaymentInvoice struct {
	Time        int64  `protobuf:"varint,1,opt,name=time" json:"time,omitempty"`
	CreatedCoin []byte `protobuf:"bytes,2,opt,name=createdCoin,proto3" json:"createdCoin,omitempty"`
	Memo        string `protobuf:"bytes,3,opt,name=memo" json:"memo,omitempty"`
}

func (m *PaymentInvoice) Reset()                    { *m = PaymentInvoice{} }
func (m *PaymentInvoice) String() string            { return proto.CompactTextString(m) }
func (*PaymentInvoice) ProtoMessage()               {}
func (*PaymentInvoice) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

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
	proto.RegisterType((*PaymentResponse)(nil), "parse.PaymentResponse")
	proto.RegisterType((*PaymentInvoice)(nil), "parse.PaymentInvoice")
	proto.RegisterEnum("parse.Type", Type_name, Type_value)
}

func init() { proto.RegisterFile("types.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 412 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x92, 0xdf, 0x8e, 0x93, 0x40,
	0x14, 0xc6, 0x85, 0xed, 0xda, 0xed, 0xa1, 0xd2, 0xd9, 0xb3, 0x5d, 0x45, 0xe3, 0x05, 0xe9, 0x55,
	0xe3, 0x85, 0x37, 0x3e, 0x41, 0x97, 0x4e, 0x5a, 0xa2, 0xa5, 0x38, 0xb0, 0x6a, 0xf7, 0x86, 0x20,
	0x9e, 0x68, 0xe3, 0xf2, 0x27, 0x0c, 0x1a, 0xfb, 0x36, 0x3e, 0xea, 0x06, 0xca, 0x74, 0x7a, 0x37,
	0xdf, 0x77, 0x7e, 0xfc, 0x98, 0x93, 0x0c, 0x58, 0xcd, 0xa1, 0x22, 0xf9, 0xbe, 0xaa, 0xcb, 0xa6,
	0xc4, 0xcb, 0x2a, 0xad, 0x25, 0xcd, 0x3e, 0x83, 0x15, 0xd3, 0xbf, 0x66, 0x43, 0x52, 0xa6, 0x3f,
	0x09, 0xa7, 0x70, 0x99, 0x95, 0x8f, 0x65, 0xed, 0x98, 0xae, 0x31, 0xbf, 0x16, 0xc7, 0x80, 0x0e,
	0x0c, 0xf3, 0x23, 0xe0, 0x5c, 0xb8, 0xc6, 0x7c, 0x24, 0x54, 0x44, 0x84, 0x41, 0xb3, 0xcf, 0xc9,
	0x19, 0xb8, 0xc6, 0xfc, 0x42, 0x74, 0xe7, 0xd9, 0x1a, 0x6c, 0xef, 0x57, 0x5a, 0x14, 0xf4, 0xa8,
	0xac, 0x6f, 0x61, 0x24, 0x2b, 0x4a, 0x7f, 0x53, 0xed, 0x2f, 0x3b, 0xc3, 0x58, 0xe8, 0xe2, 0xdc,
	0x3e, 0xe8, 0x66, 0x2a, 0xce, 0xbe, 0xc2, 0x24, 0x4c, 0x0f, 0x39, 0x15, 0x8d, 0x20, 0x59, 0x95,
	0x85, 0xa4, 0x16, 0x96, 0x7f, 0xb2, 0x8c, 0xa4, 0x74, 0x0c, 0xd7, 0x98, 0x5f, 0x09, 0x15, 0xf1,
	0x0d, 0x5c, 0xd5, 0x3d, 0xd5, 0xdd, 0x7e, 0x24, 0x4e, 0x19, 0x6d, 0x30, 0xfb, 0x3f, 0x8f, 0x84,
	0xe9, 0x2f, 0x67, 0x0f, 0x60, 0xf7, 0x62, 0xbf, 0xf8, 0x5b, 0xee, 0x33, 0xbd, 0x88, 0xa1, 0x17,
	0x41, 0x17, 0xac, 0xac, 0xa6, 0xb4, 0xa1, 0x1f, 0x5e, 0xb9, 0x2f, 0x3a, 0xe9, 0x58, 0x9c, 0x57,
	0xed, 0x57, 0x39, 0xe5, 0x65, 0x6f, 0xee, 0xce, 0xef, 0xfe, 0x9b, 0x30, 0x88, 0x0f, 0x15, 0xa1,
	0x05, 0xc3, 0x60, 0x9b, 0xc4, 0xbb, 0x90, 0xb3, 0x67, 0xc8, 0x60, 0x1c, 0xf3, 0x6f, 0x71, 0xb2,
	0xe1, 0x51, 0xb4, 0x58, 0x71, 0x66, 0xe0, 0x0d, 0x4c, 0xbc, 0xf5, 0x22, 0x08, 0xf8, 0xa7, 0x53,
	0x69, 0xb6, 0xd8, 0xfd, 0xf2, 0x2e, 0x09, 0xef, 0xa3, 0x75, 0xf2, 0x91, 0xef, 0x18, 0xe0, 0x6b,
	0xb8, 0x3d, 0x6f, 0x12, 0xc1, 0xa3, 0x70, 0x1b, 0x44, 0x9c, 0x59, 0x38, 0x01, 0xab, 0x1d, 0xad,
	0x78, 0xdc, 0xb1, 0x63, 0x74, 0x60, 0x7a, 0x56, 0x68, 0xf4, 0x85, 0xf2, 0x0a, 0xbe, 0xf2, 0xa3,
	0x98, 0x0b, 0x66, 0x2b, 0xaf, 0x6a, 0x34, 0x3c, 0x41, 0x1b, 0xa0, 0x1d, 0x45, 0x7c, 0x21, 0xbc,
	0x35, 0x63, 0xf8, 0x0a, 0x6e, 0x74, 0xd6, 0xe0, 0x75, 0xbb, 0x61, 0xb8, 0xd8, 0x6d, 0x78, 0x10,
	0xb3, 0x29, 0x4e, 0x81, 0xf5, 0x41, 0x23, 0xb7, 0xed, 0x96, 0xaa, 0xf5, 0x83, 0x2f, 0x5b, 0xdf,
	0xe3, 0xec, 0xe5, 0xdd, 0xf0, 0xe1, 0xf8, 0xfa, 0xbe, 0x3f, 0xef, 0xde, 0xe2, 0x87, 0xa7, 0x00,
	0x00, 0x00, 0xff, 0xff, 0x39, 0x30, 0xbc, 0x51, 0x9a, 0x02, 0x00, 0x00,
}
