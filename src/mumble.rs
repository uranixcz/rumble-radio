// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

use protobuf::Message as Message_imported_for_functions;
use protobuf::ProtobufEnum as ProtobufEnum_imported_for_functions;

#[derive(PartialEq,Clone,Default)]
pub struct Version {
    // message fields
    version: ::std::option::Option<u32>,
    release: ::protobuf::SingularField<::std::string::String>,
    os: ::protobuf::SingularField<::std::string::String>,
    os_version: ::protobuf::SingularField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Version {}

impl Version {
    pub fn new() -> Version {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Version {
        static mut instance: ::protobuf::lazy::Lazy<Version> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Version,
        };
        unsafe {
            instance.get(Version::new)
        }
    }

    // optional uint32 version = 1;

    pub fn clear_version(&mut self) {
        self.version = ::std::option::Option::None;
    }

    pub fn has_version(&self) -> bool {
        self.version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_version(&mut self, v: u32) {
        self.version = ::std::option::Option::Some(v);
    }

    pub fn get_version(&self) -> u32 {
        self.version.unwrap_or(0)
    }

    fn get_version_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.version
    }

    fn mut_version_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.version
    }

    // optional string release = 2;

    pub fn clear_release(&mut self) {
        self.release.clear();
    }

    pub fn has_release(&self) -> bool {
        self.release.is_some()
    }

    // Param is passed by value, moved
    pub fn set_release(&mut self, v: ::std::string::String) {
        self.release = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_release(&mut self) -> &mut ::std::string::String {
        if self.release.is_none() {
            self.release.set_default();
        }
        self.release.as_mut().unwrap()
    }

    // Take field
    pub fn take_release(&mut self) -> ::std::string::String {
        self.release.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_release(&self) -> &str {
        match self.release.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_release_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.release
    }

    fn mut_release_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.release
    }

    // optional string os = 3;

    pub fn clear_os(&mut self) {
        self.os.clear();
    }

    pub fn has_os(&self) -> bool {
        self.os.is_some()
    }

    // Param is passed by value, moved
    pub fn set_os(&mut self, v: ::std::string::String) {
        self.os = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_os(&mut self) -> &mut ::std::string::String {
        if self.os.is_none() {
            self.os.set_default();
        }
        self.os.as_mut().unwrap()
    }

    // Take field
    pub fn take_os(&mut self) -> ::std::string::String {
        self.os.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_os(&self) -> &str {
        match self.os.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_os_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.os
    }

    fn mut_os_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.os
    }

    // optional string os_version = 4;

    pub fn clear_os_version(&mut self) {
        self.os_version.clear();
    }

    pub fn has_os_version(&self) -> bool {
        self.os_version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_os_version(&mut self, v: ::std::string::String) {
        self.os_version = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_os_version(&mut self) -> &mut ::std::string::String {
        if self.os_version.is_none() {
            self.os_version.set_default();
        }
        self.os_version.as_mut().unwrap()
    }

    // Take field
    pub fn take_os_version(&mut self) -> ::std::string::String {
        self.os_version.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_os_version(&self) -> &str {
        match self.os_version.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_os_version_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.os_version
    }

    fn mut_os_version_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.os_version
    }
}

impl ::protobuf::Message for Version {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.version = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.release)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.os)?;
                },
                4 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.os_version)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.version {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.release.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        if let Some(ref v) = self.os.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(ref v) = self.os_version.as_ref() {
            my_size += ::protobuf::rt::string_size(4, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.version {
            os.write_uint32(1, v)?;
        }
        if let Some(ref v) = self.release.as_ref() {
            os.write_string(2, &v)?;
        }
        if let Some(ref v) = self.os.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(ref v) = self.os_version.as_ref() {
            os.write_string(4, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Version {
    fn new() -> Version {
        Version::new()
    }

    fn descriptor_static(_: ::std::option::Option<Version>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "version",
                    Version::get_version_for_reflect,
                    Version::mut_version_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "release",
                    Version::get_release_for_reflect,
                    Version::mut_release_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "os",
                    Version::get_os_for_reflect,
                    Version::mut_os_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "os_version",
                    Version::get_os_version_for_reflect,
                    Version::mut_os_version_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Version>(
                    "Version",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Version {
    fn clear(&mut self) {
        self.clear_version();
        self.clear_release();
        self.clear_os();
        self.clear_os_version();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Version {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Version {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UDPTunnel {
    // message fields
    packet: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UDPTunnel {}

impl UDPTunnel {
    pub fn new() -> UDPTunnel {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UDPTunnel {
        static mut instance: ::protobuf::lazy::Lazy<UDPTunnel> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UDPTunnel,
        };
        unsafe {
            instance.get(UDPTunnel::new)
        }
    }

    // required bytes packet = 1;

    pub fn clear_packet(&mut self) {
        self.packet.clear();
    }

    pub fn has_packet(&self) -> bool {
        self.packet.is_some()
    }

    // Param is passed by value, moved
    pub fn set_packet(&mut self, v: ::std::vec::Vec<u8>) {
        self.packet = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_packet(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.packet.is_none() {
            self.packet.set_default();
        }
        self.packet.as_mut().unwrap()
    }

    // Take field
    pub fn take_packet(&mut self) -> ::std::vec::Vec<u8> {
        self.packet.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_packet(&self) -> &[u8] {
        match self.packet.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_packet_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.packet
    }

    fn mut_packet_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.packet
    }
}

impl ::protobuf::Message for UDPTunnel {
    fn is_initialized(&self) -> bool {
        if self.packet.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.packet)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.packet.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.packet.as_ref() {
            os.write_bytes(1, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UDPTunnel {
    fn new() -> UDPTunnel {
        UDPTunnel::new()
    }

    fn descriptor_static(_: ::std::option::Option<UDPTunnel>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "packet",
                    UDPTunnel::get_packet_for_reflect,
                    UDPTunnel::mut_packet_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UDPTunnel>(
                    "UDPTunnel",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UDPTunnel {
    fn clear(&mut self) {
        self.clear_packet();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UDPTunnel {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UDPTunnel {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Authenticate {
    // message fields
    username: ::protobuf::SingularField<::std::string::String>,
    password: ::protobuf::SingularField<::std::string::String>,
    tokens: ::protobuf::RepeatedField<::std::string::String>,
    celt_versions: ::std::vec::Vec<i32>,
    opus: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Authenticate {}

impl Authenticate {
    pub fn new() -> Authenticate {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Authenticate {
        static mut instance: ::protobuf::lazy::Lazy<Authenticate> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Authenticate,
        };
        unsafe {
            instance.get(Authenticate::new)
        }
    }

    // optional string username = 1;

    pub fn clear_username(&mut self) {
        self.username.clear();
    }

    pub fn has_username(&self) -> bool {
        self.username.is_some()
    }

    // Param is passed by value, moved
    pub fn set_username(&mut self, v: ::std::string::String) {
        self.username = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_username(&mut self) -> &mut ::std::string::String {
        if self.username.is_none() {
            self.username.set_default();
        }
        self.username.as_mut().unwrap()
    }

    // Take field
    pub fn take_username(&mut self) -> ::std::string::String {
        self.username.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_username(&self) -> &str {
        match self.username.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_username_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.username
    }

    fn mut_username_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.username
    }

    // optional string password = 2;

    pub fn clear_password(&mut self) {
        self.password.clear();
    }

    pub fn has_password(&self) -> bool {
        self.password.is_some()
    }

    // Param is passed by value, moved
    pub fn set_password(&mut self, v: ::std::string::String) {
        self.password = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_password(&mut self) -> &mut ::std::string::String {
        if self.password.is_none() {
            self.password.set_default();
        }
        self.password.as_mut().unwrap()
    }

    // Take field
    pub fn take_password(&mut self) -> ::std::string::String {
        self.password.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_password(&self) -> &str {
        match self.password.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_password_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.password
    }

    fn mut_password_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.password
    }

    // repeated string tokens = 3;

    pub fn clear_tokens(&mut self) {
        self.tokens.clear();
    }

    // Param is passed by value, moved
    pub fn set_tokens(&mut self, v: ::protobuf::RepeatedField<::std::string::String>) {
        self.tokens = v;
    }

    // Mutable pointer to the field.
    pub fn mut_tokens(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.tokens
    }

    // Take field
    pub fn take_tokens(&mut self) -> ::protobuf::RepeatedField<::std::string::String> {
        ::std::mem::replace(&mut self.tokens, ::protobuf::RepeatedField::new())
    }

    pub fn get_tokens(&self) -> &[::std::string::String] {
        &self.tokens
    }

    fn get_tokens_for_reflect(&self) -> &::protobuf::RepeatedField<::std::string::String> {
        &self.tokens
    }

    fn mut_tokens_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.tokens
    }

    // repeated int32 celt_versions = 4;

    pub fn clear_celt_versions(&mut self) {
        self.celt_versions.clear();
    }

    // Param is passed by value, moved
    pub fn set_celt_versions(&mut self, v: ::std::vec::Vec<i32>) {
        self.celt_versions = v;
    }

    // Mutable pointer to the field.
    pub fn mut_celt_versions(&mut self) -> &mut ::std::vec::Vec<i32> {
        &mut self.celt_versions
    }

    // Take field
    pub fn take_celt_versions(&mut self) -> ::std::vec::Vec<i32> {
        ::std::mem::replace(&mut self.celt_versions, ::std::vec::Vec::new())
    }

    pub fn get_celt_versions(&self) -> &[i32] {
        &self.celt_versions
    }

    fn get_celt_versions_for_reflect(&self) -> &::std::vec::Vec<i32> {
        &self.celt_versions
    }

    fn mut_celt_versions_for_reflect(&mut self) -> &mut ::std::vec::Vec<i32> {
        &mut self.celt_versions
    }

    // optional bool opus = 5;

    pub fn clear_opus(&mut self) {
        self.opus = ::std::option::Option::None;
    }

    pub fn has_opus(&self) -> bool {
        self.opus.is_some()
    }

    // Param is passed by value, moved
    pub fn set_opus(&mut self, v: bool) {
        self.opus = ::std::option::Option::Some(v);
    }

    pub fn get_opus(&self) -> bool {
        self.opus.unwrap_or(false)
    }

    fn get_opus_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.opus
    }

    fn mut_opus_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.opus
    }
}

impl ::protobuf::Message for Authenticate {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.username)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.password)?;
                },
                3 => {
                    ::protobuf::rt::read_repeated_string_into(wire_type, is, &mut self.tokens)?;
                },
                4 => {
                    ::protobuf::rt::read_repeated_int32_into(wire_type, is, &mut self.celt_versions)?;
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.opus = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.username.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(ref v) = self.password.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        for value in &self.tokens {
            my_size += ::protobuf::rt::string_size(3, &value);
        };
        for value in &self.celt_versions {
            my_size += ::protobuf::rt::value_size(4, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(v) = self.opus {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.username.as_ref() {
            os.write_string(1, &v)?;
        }
        if let Some(ref v) = self.password.as_ref() {
            os.write_string(2, &v)?;
        }
        for v in &self.tokens {
            os.write_string(3, &v)?;
        };
        for v in &self.celt_versions {
            os.write_int32(4, *v)?;
        };
        if let Some(v) = self.opus {
            os.write_bool(5, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Authenticate {
    fn new() -> Authenticate {
        Authenticate::new()
    }

    fn descriptor_static(_: ::std::option::Option<Authenticate>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "username",
                    Authenticate::get_username_for_reflect,
                    Authenticate::mut_username_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "password",
                    Authenticate::get_password_for_reflect,
                    Authenticate::mut_password_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "tokens",
                    Authenticate::get_tokens_for_reflect,
                    Authenticate::mut_tokens_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "celt_versions",
                    Authenticate::get_celt_versions_for_reflect,
                    Authenticate::mut_celt_versions_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "opus",
                    Authenticate::get_opus_for_reflect,
                    Authenticate::mut_opus_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Authenticate>(
                    "Authenticate",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Authenticate {
    fn clear(&mut self) {
        self.clear_username();
        self.clear_password();
        self.clear_tokens();
        self.clear_celt_versions();
        self.clear_opus();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Authenticate {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Authenticate {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Ping {
    // message fields
    timestamp: ::std::option::Option<u64>,
    good: ::std::option::Option<u32>,
    late: ::std::option::Option<u32>,
    lost: ::std::option::Option<u32>,
    resync: ::std::option::Option<u32>,
    udp_packets: ::std::option::Option<u32>,
    tcp_packets: ::std::option::Option<u32>,
    udp_ping_avg: ::std::option::Option<f32>,
    udp_ping_var: ::std::option::Option<f32>,
    tcp_ping_avg: ::std::option::Option<f32>,
    tcp_ping_var: ::std::option::Option<f32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Ping {}

impl Ping {
    pub fn new() -> Ping {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Ping {
        static mut instance: ::protobuf::lazy::Lazy<Ping> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Ping,
        };
        unsafe {
            instance.get(Ping::new)
        }
    }

    // optional uint64 timestamp = 1;

    pub fn clear_timestamp(&mut self) {
        self.timestamp = ::std::option::Option::None;
    }

    pub fn has_timestamp(&self) -> bool {
        self.timestamp.is_some()
    }

    // Param is passed by value, moved
    pub fn set_timestamp(&mut self, v: u64) {
        self.timestamp = ::std::option::Option::Some(v);
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp.unwrap_or(0)
    }

    fn get_timestamp_for_reflect(&self) -> &::std::option::Option<u64> {
        &self.timestamp
    }

    fn mut_timestamp_for_reflect(&mut self) -> &mut ::std::option::Option<u64> {
        &mut self.timestamp
    }

    // optional uint32 good = 2;

    pub fn clear_good(&mut self) {
        self.good = ::std::option::Option::None;
    }

    pub fn has_good(&self) -> bool {
        self.good.is_some()
    }

    // Param is passed by value, moved
    pub fn set_good(&mut self, v: u32) {
        self.good = ::std::option::Option::Some(v);
    }

    pub fn get_good(&self) -> u32 {
        self.good.unwrap_or(0)
    }

    fn get_good_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.good
    }

    fn mut_good_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.good
    }

    // optional uint32 late = 3;

    pub fn clear_late(&mut self) {
        self.late = ::std::option::Option::None;
    }

    pub fn has_late(&self) -> bool {
        self.late.is_some()
    }

    // Param is passed by value, moved
    pub fn set_late(&mut self, v: u32) {
        self.late = ::std::option::Option::Some(v);
    }

    pub fn get_late(&self) -> u32 {
        self.late.unwrap_or(0)
    }

    fn get_late_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.late
    }

    fn mut_late_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.late
    }

    // optional uint32 lost = 4;

    pub fn clear_lost(&mut self) {
        self.lost = ::std::option::Option::None;
    }

    pub fn has_lost(&self) -> bool {
        self.lost.is_some()
    }

    // Param is passed by value, moved
    pub fn set_lost(&mut self, v: u32) {
        self.lost = ::std::option::Option::Some(v);
    }

    pub fn get_lost(&self) -> u32 {
        self.lost.unwrap_or(0)
    }

    fn get_lost_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.lost
    }

    fn mut_lost_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.lost
    }

    // optional uint32 resync = 5;

    pub fn clear_resync(&mut self) {
        self.resync = ::std::option::Option::None;
    }

    pub fn has_resync(&self) -> bool {
        self.resync.is_some()
    }

    // Param is passed by value, moved
    pub fn set_resync(&mut self, v: u32) {
        self.resync = ::std::option::Option::Some(v);
    }

    pub fn get_resync(&self) -> u32 {
        self.resync.unwrap_or(0)
    }

    fn get_resync_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.resync
    }

    fn mut_resync_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.resync
    }

    // optional uint32 udp_packets = 6;

    pub fn clear_udp_packets(&mut self) {
        self.udp_packets = ::std::option::Option::None;
    }

    pub fn has_udp_packets(&self) -> bool {
        self.udp_packets.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_packets(&mut self, v: u32) {
        self.udp_packets = ::std::option::Option::Some(v);
    }

    pub fn get_udp_packets(&self) -> u32 {
        self.udp_packets.unwrap_or(0)
    }

    fn get_udp_packets_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.udp_packets
    }

    fn mut_udp_packets_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.udp_packets
    }

    // optional uint32 tcp_packets = 7;

    pub fn clear_tcp_packets(&mut self) {
        self.tcp_packets = ::std::option::Option::None;
    }

    pub fn has_tcp_packets(&self) -> bool {
        self.tcp_packets.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_packets(&mut self, v: u32) {
        self.tcp_packets = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_packets(&self) -> u32 {
        self.tcp_packets.unwrap_or(0)
    }

    fn get_tcp_packets_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tcp_packets
    }

    fn mut_tcp_packets_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tcp_packets
    }

    // optional float udp_ping_avg = 8;

    pub fn clear_udp_ping_avg(&mut self) {
        self.udp_ping_avg = ::std::option::Option::None;
    }

    pub fn has_udp_ping_avg(&self) -> bool {
        self.udp_ping_avg.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_ping_avg(&mut self, v: f32) {
        self.udp_ping_avg = ::std::option::Option::Some(v);
    }

    pub fn get_udp_ping_avg(&self) -> f32 {
        self.udp_ping_avg.unwrap_or(0.)
    }

    fn get_udp_ping_avg_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.udp_ping_avg
    }

    fn mut_udp_ping_avg_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.udp_ping_avg
    }

    // optional float udp_ping_var = 9;

    pub fn clear_udp_ping_var(&mut self) {
        self.udp_ping_var = ::std::option::Option::None;
    }

    pub fn has_udp_ping_var(&self) -> bool {
        self.udp_ping_var.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_ping_var(&mut self, v: f32) {
        self.udp_ping_var = ::std::option::Option::Some(v);
    }

    pub fn get_udp_ping_var(&self) -> f32 {
        self.udp_ping_var.unwrap_or(0.)
    }

    fn get_udp_ping_var_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.udp_ping_var
    }

    fn mut_udp_ping_var_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.udp_ping_var
    }

    // optional float tcp_ping_avg = 10;

    pub fn clear_tcp_ping_avg(&mut self) {
        self.tcp_ping_avg = ::std::option::Option::None;
    }

    pub fn has_tcp_ping_avg(&self) -> bool {
        self.tcp_ping_avg.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_ping_avg(&mut self, v: f32) {
        self.tcp_ping_avg = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_ping_avg(&self) -> f32 {
        self.tcp_ping_avg.unwrap_or(0.)
    }

    fn get_tcp_ping_avg_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.tcp_ping_avg
    }

    fn mut_tcp_ping_avg_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.tcp_ping_avg
    }

    // optional float tcp_ping_var = 11;

    pub fn clear_tcp_ping_var(&mut self) {
        self.tcp_ping_var = ::std::option::Option::None;
    }

    pub fn has_tcp_ping_var(&self) -> bool {
        self.tcp_ping_var.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_ping_var(&mut self, v: f32) {
        self.tcp_ping_var = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_ping_var(&self) -> f32 {
        self.tcp_ping_var.unwrap_or(0.)
    }

    fn get_tcp_ping_var_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.tcp_ping_var
    }

    fn mut_tcp_ping_var_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.tcp_ping_var
    }
}

impl ::protobuf::Message for Ping {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.timestamp = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.good = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.late = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.lost = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.resync = ::std::option::Option::Some(tmp);
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.udp_packets = ::std::option::Option::Some(tmp);
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tcp_packets = ::std::option::Option::Some(tmp);
                },
                8 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.udp_ping_avg = ::std::option::Option::Some(tmp);
                },
                9 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.udp_ping_var = ::std::option::Option::Some(tmp);
                },
                10 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.tcp_ping_avg = ::std::option::Option::Some(tmp);
                },
                11 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.tcp_ping_var = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.timestamp {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.good {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.late {
            my_size += ::protobuf::rt::value_size(3, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.lost {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.resync {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.udp_packets {
            my_size += ::protobuf::rt::value_size(6, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.tcp_packets {
            my_size += ::protobuf::rt::value_size(7, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.udp_ping_avg {
            my_size += 5;
        }
        if let Some(v) = self.udp_ping_var {
            my_size += 5;
        }
        if let Some(v) = self.tcp_ping_avg {
            my_size += 5;
        }
        if let Some(v) = self.tcp_ping_var {
            my_size += 5;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.timestamp {
            os.write_uint64(1, v)?;
        }
        if let Some(v) = self.good {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.late {
            os.write_uint32(3, v)?;
        }
        if let Some(v) = self.lost {
            os.write_uint32(4, v)?;
        }
        if let Some(v) = self.resync {
            os.write_uint32(5, v)?;
        }
        if let Some(v) = self.udp_packets {
            os.write_uint32(6, v)?;
        }
        if let Some(v) = self.tcp_packets {
            os.write_uint32(7, v)?;
        }
        if let Some(v) = self.udp_ping_avg {
            os.write_float(8, v)?;
        }
        if let Some(v) = self.udp_ping_var {
            os.write_float(9, v)?;
        }
        if let Some(v) = self.tcp_ping_avg {
            os.write_float(10, v)?;
        }
        if let Some(v) = self.tcp_ping_var {
            os.write_float(11, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Ping {
    fn new() -> Ping {
        Ping::new()
    }

    fn descriptor_static(_: ::std::option::Option<Ping>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "timestamp",
                    Ping::get_timestamp_for_reflect,
                    Ping::mut_timestamp_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "good",
                    Ping::get_good_for_reflect,
                    Ping::mut_good_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "late",
                    Ping::get_late_for_reflect,
                    Ping::mut_late_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "lost",
                    Ping::get_lost_for_reflect,
                    Ping::mut_lost_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "resync",
                    Ping::get_resync_for_reflect,
                    Ping::mut_resync_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "udp_packets",
                    Ping::get_udp_packets_for_reflect,
                    Ping::mut_udp_packets_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tcp_packets",
                    Ping::get_tcp_packets_for_reflect,
                    Ping::mut_tcp_packets_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "udp_ping_avg",
                    Ping::get_udp_ping_avg_for_reflect,
                    Ping::mut_udp_ping_avg_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "udp_ping_var",
                    Ping::get_udp_ping_var_for_reflect,
                    Ping::mut_udp_ping_var_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "tcp_ping_avg",
                    Ping::get_tcp_ping_avg_for_reflect,
                    Ping::mut_tcp_ping_avg_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "tcp_ping_var",
                    Ping::get_tcp_ping_var_for_reflect,
                    Ping::mut_tcp_ping_var_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Ping>(
                    "Ping",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Ping {
    fn clear(&mut self) {
        self.clear_timestamp();
        self.clear_good();
        self.clear_late();
        self.clear_lost();
        self.clear_resync();
        self.clear_udp_packets();
        self.clear_tcp_packets();
        self.clear_udp_ping_avg();
        self.clear_udp_ping_var();
        self.clear_tcp_ping_avg();
        self.clear_tcp_ping_var();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Ping {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Ping {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct Reject {
    // message fields
    field_type: ::std::option::Option<Reject_RejectType>,
    reason: ::protobuf::SingularField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for Reject {}

impl Reject {
    pub fn new() -> Reject {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static Reject {
        static mut instance: ::protobuf::lazy::Lazy<Reject> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const Reject,
        };
        unsafe {
            instance.get(Reject::new)
        }
    }

    // optional .MumbleProto.Reject.RejectType type = 1;

    pub fn clear_field_type(&mut self) {
        self.field_type = ::std::option::Option::None;
    }

    pub fn has_field_type(&self) -> bool {
        self.field_type.is_some()
    }

    // Param is passed by value, moved
    pub fn set_field_type(&mut self, v: Reject_RejectType) {
        self.field_type = ::std::option::Option::Some(v);
    }

    pub fn get_field_type(&self) -> Reject_RejectType {
        self.field_type.unwrap_or(Reject_RejectType::None)
    }

    fn get_field_type_for_reflect(&self) -> &::std::option::Option<Reject_RejectType> {
        &self.field_type
    }

    fn mut_field_type_for_reflect(&mut self) -> &mut ::std::option::Option<Reject_RejectType> {
        &mut self.field_type
    }

    // optional string reason = 2;

    pub fn clear_reason(&mut self) {
        self.reason.clear();
    }

    pub fn has_reason(&self) -> bool {
        self.reason.is_some()
    }

    // Param is passed by value, moved
    pub fn set_reason(&mut self, v: ::std::string::String) {
        self.reason = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_reason(&mut self) -> &mut ::std::string::String {
        if self.reason.is_none() {
            self.reason.set_default();
        }
        self.reason.as_mut().unwrap()
    }

    // Take field
    pub fn take_reason(&mut self) -> ::std::string::String {
        self.reason.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_reason(&self) -> &str {
        match self.reason.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_reason_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.reason
    }

    fn mut_reason_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.reason
    }
}

impl ::protobuf::Message for Reject {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.field_type = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.reason)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.field_type {
            my_size += ::protobuf::rt::enum_size(1, v);
        }
        if let Some(ref v) = self.reason.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.field_type {
            os.write_enum(1, v.value())?;
        }
        if let Some(ref v) = self.reason.as_ref() {
            os.write_string(2, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for Reject {
    fn new() -> Reject {
        Reject::new()
    }

    fn descriptor_static(_: ::std::option::Option<Reject>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<Reject_RejectType>>(
                    "type",
                    Reject::get_field_type_for_reflect,
                    Reject::mut_field_type_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "reason",
                    Reject::get_reason_for_reflect,
                    Reject::mut_reason_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<Reject>(
                    "Reject",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for Reject {
    fn clear(&mut self) {
        self.clear_field_type();
        self.clear_reason();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for Reject {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for Reject {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum Reject_RejectType {
    None = 0,
    WrongVersion = 1,
    InvalidUsername = 2,
    WrongUserPW = 3,
    WrongServerPW = 4,
    UsernameInUse = 5,
    ServerFull = 6,
    NoCertificate = 7,
    AuthenticatorFail = 8,
}

impl ::protobuf::ProtobufEnum for Reject_RejectType {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<Reject_RejectType> {
        match value {
            0 => ::std::option::Option::Some(Reject_RejectType::None),
            1 => ::std::option::Option::Some(Reject_RejectType::WrongVersion),
            2 => ::std::option::Option::Some(Reject_RejectType::InvalidUsername),
            3 => ::std::option::Option::Some(Reject_RejectType::WrongUserPW),
            4 => ::std::option::Option::Some(Reject_RejectType::WrongServerPW),
            5 => ::std::option::Option::Some(Reject_RejectType::UsernameInUse),
            6 => ::std::option::Option::Some(Reject_RejectType::ServerFull),
            7 => ::std::option::Option::Some(Reject_RejectType::NoCertificate),
            8 => ::std::option::Option::Some(Reject_RejectType::AuthenticatorFail),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [Reject_RejectType] = &[
            Reject_RejectType::None,
            Reject_RejectType::WrongVersion,
            Reject_RejectType::InvalidUsername,
            Reject_RejectType::WrongUserPW,
            Reject_RejectType::WrongServerPW,
            Reject_RejectType::UsernameInUse,
            Reject_RejectType::ServerFull,
            Reject_RejectType::NoCertificate,
            Reject_RejectType::AuthenticatorFail,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<Reject_RejectType>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("Reject_RejectType", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for Reject_RejectType {
}

impl ::protobuf::reflect::ProtobufValue for Reject_RejectType {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ServerSync {
    // message fields
    session: ::std::option::Option<u32>,
    max_bandwidth: ::std::option::Option<u32>,
    welcome_text: ::protobuf::SingularField<::std::string::String>,
    permissions: ::std::option::Option<u64>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ServerSync {}

impl ServerSync {
    pub fn new() -> ServerSync {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ServerSync {
        static mut instance: ::protobuf::lazy::Lazy<ServerSync> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ServerSync,
        };
        unsafe {
            instance.get(ServerSync::new)
        }
    }

    // optional uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional uint32 max_bandwidth = 2;

    pub fn clear_max_bandwidth(&mut self) {
        self.max_bandwidth = ::std::option::Option::None;
    }

    pub fn has_max_bandwidth(&self) -> bool {
        self.max_bandwidth.is_some()
    }

    // Param is passed by value, moved
    pub fn set_max_bandwidth(&mut self, v: u32) {
        self.max_bandwidth = ::std::option::Option::Some(v);
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.max_bandwidth.unwrap_or(0)
    }

    fn get_max_bandwidth_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.max_bandwidth
    }

    fn mut_max_bandwidth_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.max_bandwidth
    }

    // optional string welcome_text = 3;

    pub fn clear_welcome_text(&mut self) {
        self.welcome_text.clear();
    }

    pub fn has_welcome_text(&self) -> bool {
        self.welcome_text.is_some()
    }

    // Param is passed by value, moved
    pub fn set_welcome_text(&mut self, v: ::std::string::String) {
        self.welcome_text = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_welcome_text(&mut self) -> &mut ::std::string::String {
        if self.welcome_text.is_none() {
            self.welcome_text.set_default();
        }
        self.welcome_text.as_mut().unwrap()
    }

    // Take field
    pub fn take_welcome_text(&mut self) -> ::std::string::String {
        self.welcome_text.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_welcome_text(&self) -> &str {
        match self.welcome_text.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_welcome_text_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.welcome_text
    }

    fn mut_welcome_text_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.welcome_text
    }

    // optional uint64 permissions = 4;

    pub fn clear_permissions(&mut self) {
        self.permissions = ::std::option::Option::None;
    }

    pub fn has_permissions(&self) -> bool {
        self.permissions.is_some()
    }

    // Param is passed by value, moved
    pub fn set_permissions(&mut self, v: u64) {
        self.permissions = ::std::option::Option::Some(v);
    }

    pub fn get_permissions(&self) -> u64 {
        self.permissions.unwrap_or(0)
    }

    fn get_permissions_for_reflect(&self) -> &::std::option::Option<u64> {
        &self.permissions
    }

    fn mut_permissions_for_reflect(&mut self) -> &mut ::std::option::Option<u64> {
        &mut self.permissions
    }
}

impl ::protobuf::Message for ServerSync {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.max_bandwidth = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.welcome_text)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint64()?;
                    self.permissions = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.max_bandwidth {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.welcome_text.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.permissions {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.session {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.max_bandwidth {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.welcome_text.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(v) = self.permissions {
            os.write_uint64(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ServerSync {
    fn new() -> ServerSync {
        ServerSync::new()
    }

    fn descriptor_static(_: ::std::option::Option<ServerSync>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    ServerSync::get_session_for_reflect,
                    ServerSync::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "max_bandwidth",
                    ServerSync::get_max_bandwidth_for_reflect,
                    ServerSync::mut_max_bandwidth_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "welcome_text",
                    ServerSync::get_welcome_text_for_reflect,
                    ServerSync::mut_welcome_text_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint64>(
                    "permissions",
                    ServerSync::get_permissions_for_reflect,
                    ServerSync::mut_permissions_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ServerSync>(
                    "ServerSync",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ServerSync {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_max_bandwidth();
        self.clear_welcome_text();
        self.clear_permissions();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ServerSync {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ServerSync {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ChannelRemove {
    // message fields
    channel_id: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ChannelRemove {}

impl ChannelRemove {
    pub fn new() -> ChannelRemove {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ChannelRemove {
        static mut instance: ::protobuf::lazy::Lazy<ChannelRemove> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ChannelRemove,
        };
        unsafe {
            instance.get(ChannelRemove::new)
        }
    }

    // required uint32 channel_id = 1;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }
}

impl ::protobuf::Message for ChannelRemove {
    fn is_initialized(&self) -> bool {
        if self.channel_id.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.channel_id {
            os.write_uint32(1, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ChannelRemove {
    fn new() -> ChannelRemove {
        ChannelRemove::new()
    }

    fn descriptor_static(_: ::std::option::Option<ChannelRemove>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    ChannelRemove::get_channel_id_for_reflect,
                    ChannelRemove::mut_channel_id_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ChannelRemove>(
                    "ChannelRemove",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ChannelRemove {
    fn clear(&mut self) {
        self.clear_channel_id();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ChannelRemove {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ChannelRemove {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ChannelState {
    // message fields
    channel_id: ::std::option::Option<u32>,
    parent: ::std::option::Option<u32>,
    name: ::protobuf::SingularField<::std::string::String>,
    links: ::std::vec::Vec<u32>,
    description: ::protobuf::SingularField<::std::string::String>,
    links_add: ::std::vec::Vec<u32>,
    links_remove: ::std::vec::Vec<u32>,
    temporary: ::std::option::Option<bool>,
    position: ::std::option::Option<i32>,
    description_hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    max_users: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ChannelState {}

impl ChannelState {
    pub fn new() -> ChannelState {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ChannelState {
        static mut instance: ::protobuf::lazy::Lazy<ChannelState> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ChannelState,
        };
        unsafe {
            instance.get(ChannelState::new)
        }
    }

    // optional uint32 channel_id = 1;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional uint32 parent = 2;

    pub fn clear_parent(&mut self) {
        self.parent = ::std::option::Option::None;
    }

    pub fn has_parent(&self) -> bool {
        self.parent.is_some()
    }

    // Param is passed by value, moved
    pub fn set_parent(&mut self, v: u32) {
        self.parent = ::std::option::Option::Some(v);
    }

    pub fn get_parent(&self) -> u32 {
        self.parent.unwrap_or(0)
    }

    fn get_parent_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.parent
    }

    fn mut_parent_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.parent
    }

    // optional string name = 3;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }

    // repeated uint32 links = 4;

    pub fn clear_links(&mut self) {
        self.links.clear();
    }

    // Param is passed by value, moved
    pub fn set_links(&mut self, v: ::std::vec::Vec<u32>) {
        self.links = v;
    }

    // Mutable pointer to the field.
    pub fn mut_links(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links
    }

    // Take field
    pub fn take_links(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.links, ::std::vec::Vec::new())
    }

    pub fn get_links(&self) -> &[u32] {
        &self.links
    }

    fn get_links_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.links
    }

    fn mut_links_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links
    }

    // optional string description = 5;

    pub fn clear_description(&mut self) {
        self.description.clear();
    }

    pub fn has_description(&self) -> bool {
        self.description.is_some()
    }

    // Param is passed by value, moved
    pub fn set_description(&mut self, v: ::std::string::String) {
        self.description = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_description(&mut self) -> &mut ::std::string::String {
        if self.description.is_none() {
            self.description.set_default();
        }
        self.description.as_mut().unwrap()
    }

    // Take field
    pub fn take_description(&mut self) -> ::std::string::String {
        self.description.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_description(&self) -> &str {
        match self.description.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_description_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.description
    }

    fn mut_description_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.description
    }

    // repeated uint32 links_add = 6;

    pub fn clear_links_add(&mut self) {
        self.links_add.clear();
    }

    // Param is passed by value, moved
    pub fn set_links_add(&mut self, v: ::std::vec::Vec<u32>) {
        self.links_add = v;
    }

    // Mutable pointer to the field.
    pub fn mut_links_add(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links_add
    }

    // Take field
    pub fn take_links_add(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.links_add, ::std::vec::Vec::new())
    }

    pub fn get_links_add(&self) -> &[u32] {
        &self.links_add
    }

    fn get_links_add_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.links_add
    }

    fn mut_links_add_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links_add
    }

    // repeated uint32 links_remove = 7;

    pub fn clear_links_remove(&mut self) {
        self.links_remove.clear();
    }

    // Param is passed by value, moved
    pub fn set_links_remove(&mut self, v: ::std::vec::Vec<u32>) {
        self.links_remove = v;
    }

    // Mutable pointer to the field.
    pub fn mut_links_remove(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links_remove
    }

    // Take field
    pub fn take_links_remove(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.links_remove, ::std::vec::Vec::new())
    }

    pub fn get_links_remove(&self) -> &[u32] {
        &self.links_remove
    }

    fn get_links_remove_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.links_remove
    }

    fn mut_links_remove_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.links_remove
    }

    // optional bool temporary = 8;

    pub fn clear_temporary(&mut self) {
        self.temporary = ::std::option::Option::None;
    }

    pub fn has_temporary(&self) -> bool {
        self.temporary.is_some()
    }

    // Param is passed by value, moved
    pub fn set_temporary(&mut self, v: bool) {
        self.temporary = ::std::option::Option::Some(v);
    }

    pub fn get_temporary(&self) -> bool {
        self.temporary.unwrap_or(false)
    }

    fn get_temporary_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.temporary
    }

    fn mut_temporary_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.temporary
    }

    // optional int32 position = 9;

    pub fn clear_position(&mut self) {
        self.position = ::std::option::Option::None;
    }

    pub fn has_position(&self) -> bool {
        self.position.is_some()
    }

    // Param is passed by value, moved
    pub fn set_position(&mut self, v: i32) {
        self.position = ::std::option::Option::Some(v);
    }

    pub fn get_position(&self) -> i32 {
        self.position.unwrap_or(0i32)
    }

    fn get_position_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.position
    }

    fn mut_position_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.position
    }

    // optional bytes description_hash = 10;

    pub fn clear_description_hash(&mut self) {
        self.description_hash.clear();
    }

    pub fn has_description_hash(&self) -> bool {
        self.description_hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_description_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.description_hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_description_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.description_hash.is_none() {
            self.description_hash.set_default();
        }
        self.description_hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_description_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.description_hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_description_hash(&self) -> &[u8] {
        match self.description_hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_description_hash_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.description_hash
    }

    fn mut_description_hash_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.description_hash
    }

    // optional uint32 max_users = 11;

    pub fn clear_max_users(&mut self) {
        self.max_users = ::std::option::Option::None;
    }

    pub fn has_max_users(&self) -> bool {
        self.max_users.is_some()
    }

    // Param is passed by value, moved
    pub fn set_max_users(&mut self, v: u32) {
        self.max_users = ::std::option::Option::Some(v);
    }

    pub fn get_max_users(&self) -> u32 {
        self.max_users.unwrap_or(0)
    }

    fn get_max_users_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.max_users
    }

    fn mut_max_users_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.max_users
    }
}

impl ::protobuf::Message for ChannelState {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.parent = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                4 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.links)?;
                },
                5 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.description)?;
                },
                6 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.links_add)?;
                },
                7 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.links_remove)?;
                },
                8 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.temporary = ::std::option::Option::Some(tmp);
                },
                9 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.position = ::std::option::Option::Some(tmp);
                },
                10 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.description_hash)?;
                },
                11 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.max_users = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.parent {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        for value in &self.links {
            my_size += ::protobuf::rt::value_size(4, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(ref v) = self.description.as_ref() {
            my_size += ::protobuf::rt::string_size(5, &v);
        }
        for value in &self.links_add {
            my_size += ::protobuf::rt::value_size(6, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.links_remove {
            my_size += ::protobuf::rt::value_size(7, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(v) = self.temporary {
            my_size += 2;
        }
        if let Some(v) = self.position {
            my_size += ::protobuf::rt::value_size(9, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.description_hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(10, &v);
        }
        if let Some(v) = self.max_users {
            my_size += ::protobuf::rt::value_size(11, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.channel_id {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.parent {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(3, &v)?;
        }
        for v in &self.links {
            os.write_uint32(4, *v)?;
        };
        if let Some(ref v) = self.description.as_ref() {
            os.write_string(5, &v)?;
        }
        for v in &self.links_add {
            os.write_uint32(6, *v)?;
        };
        for v in &self.links_remove {
            os.write_uint32(7, *v)?;
        };
        if let Some(v) = self.temporary {
            os.write_bool(8, v)?;
        }
        if let Some(v) = self.position {
            os.write_int32(9, v)?;
        }
        if let Some(ref v) = self.description_hash.as_ref() {
            os.write_bytes(10, &v)?;
        }
        if let Some(v) = self.max_users {
            os.write_uint32(11, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ChannelState {
    fn new() -> ChannelState {
        ChannelState::new()
    }

    fn descriptor_static(_: ::std::option::Option<ChannelState>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    ChannelState::get_channel_id_for_reflect,
                    ChannelState::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "parent",
                    ChannelState::get_parent_for_reflect,
                    ChannelState::mut_parent_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    ChannelState::get_name_for_reflect,
                    ChannelState::mut_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "links",
                    ChannelState::get_links_for_reflect,
                    ChannelState::mut_links_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "description",
                    ChannelState::get_description_for_reflect,
                    ChannelState::mut_description_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "links_add",
                    ChannelState::get_links_add_for_reflect,
                    ChannelState::mut_links_add_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "links_remove",
                    ChannelState::get_links_remove_for_reflect,
                    ChannelState::mut_links_remove_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "temporary",
                    ChannelState::get_temporary_for_reflect,
                    ChannelState::mut_temporary_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "position",
                    ChannelState::get_position_for_reflect,
                    ChannelState::mut_position_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "description_hash",
                    ChannelState::get_description_hash_for_reflect,
                    ChannelState::mut_description_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "max_users",
                    ChannelState::get_max_users_for_reflect,
                    ChannelState::mut_max_users_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ChannelState>(
                    "ChannelState",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ChannelState {
    fn clear(&mut self) {
        self.clear_channel_id();
        self.clear_parent();
        self.clear_name();
        self.clear_links();
        self.clear_description();
        self.clear_links_add();
        self.clear_links_remove();
        self.clear_temporary();
        self.clear_position();
        self.clear_description_hash();
        self.clear_max_users();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ChannelState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ChannelState {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserRemove {
    // message fields
    session: ::std::option::Option<u32>,
    actor: ::std::option::Option<u32>,
    reason: ::protobuf::SingularField<::std::string::String>,
    ban: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserRemove {}

impl UserRemove {
    pub fn new() -> UserRemove {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserRemove {
        static mut instance: ::protobuf::lazy::Lazy<UserRemove> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserRemove,
        };
        unsafe {
            instance.get(UserRemove::new)
        }
    }

    // required uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional uint32 actor = 2;

    pub fn clear_actor(&mut self) {
        self.actor = ::std::option::Option::None;
    }

    pub fn has_actor(&self) -> bool {
        self.actor.is_some()
    }

    // Param is passed by value, moved
    pub fn set_actor(&mut self, v: u32) {
        self.actor = ::std::option::Option::Some(v);
    }

    pub fn get_actor(&self) -> u32 {
        self.actor.unwrap_or(0)
    }

    fn get_actor_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.actor
    }

    fn mut_actor_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.actor
    }

    // optional string reason = 3;

    pub fn clear_reason(&mut self) {
        self.reason.clear();
    }

    pub fn has_reason(&self) -> bool {
        self.reason.is_some()
    }

    // Param is passed by value, moved
    pub fn set_reason(&mut self, v: ::std::string::String) {
        self.reason = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_reason(&mut self) -> &mut ::std::string::String {
        if self.reason.is_none() {
            self.reason.set_default();
        }
        self.reason.as_mut().unwrap()
    }

    // Take field
    pub fn take_reason(&mut self) -> ::std::string::String {
        self.reason.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_reason(&self) -> &str {
        match self.reason.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_reason_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.reason
    }

    fn mut_reason_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.reason
    }

    // optional bool ban = 4;

    pub fn clear_ban(&mut self) {
        self.ban = ::std::option::Option::None;
    }

    pub fn has_ban(&self) -> bool {
        self.ban.is_some()
    }

    // Param is passed by value, moved
    pub fn set_ban(&mut self, v: bool) {
        self.ban = ::std::option::Option::Some(v);
    }

    pub fn get_ban(&self) -> bool {
        self.ban.unwrap_or(false)
    }

    fn get_ban_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.ban
    }

    fn mut_ban_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.ban
    }
}

impl ::protobuf::Message for UserRemove {
    fn is_initialized(&self) -> bool {
        if self.session.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.actor = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.reason)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.ban = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.actor {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.reason.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.ban {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.session {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.actor {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.reason.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(v) = self.ban {
            os.write_bool(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserRemove {
    fn new() -> UserRemove {
        UserRemove::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserRemove>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    UserRemove::get_session_for_reflect,
                    UserRemove::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "actor",
                    UserRemove::get_actor_for_reflect,
                    UserRemove::mut_actor_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "reason",
                    UserRemove::get_reason_for_reflect,
                    UserRemove::mut_reason_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "ban",
                    UserRemove::get_ban_for_reflect,
                    UserRemove::mut_ban_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserRemove>(
                    "UserRemove",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserRemove {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_actor();
        self.clear_reason();
        self.clear_ban();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserRemove {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserRemove {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserState {
    // message fields
    session: ::std::option::Option<u32>,
    actor: ::std::option::Option<u32>,
    name: ::protobuf::SingularField<::std::string::String>,
    user_id: ::std::option::Option<u32>,
    channel_id: ::std::option::Option<u32>,
    mute: ::std::option::Option<bool>,
    deaf: ::std::option::Option<bool>,
    suppress: ::std::option::Option<bool>,
    self_mute: ::std::option::Option<bool>,
    self_deaf: ::std::option::Option<bool>,
    texture: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    plugin_context: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    plugin_identity: ::protobuf::SingularField<::std::string::String>,
    comment: ::protobuf::SingularField<::std::string::String>,
    hash: ::protobuf::SingularField<::std::string::String>,
    comment_hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    texture_hash: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    priority_speaker: ::std::option::Option<bool>,
    recording: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserState {}

impl UserState {
    pub fn new() -> UserState {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserState {
        static mut instance: ::protobuf::lazy::Lazy<UserState> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserState,
        };
        unsafe {
            instance.get(UserState::new)
        }
    }

    // optional uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional uint32 actor = 2;

    pub fn clear_actor(&mut self) {
        self.actor = ::std::option::Option::None;
    }

    pub fn has_actor(&self) -> bool {
        self.actor.is_some()
    }

    // Param is passed by value, moved
    pub fn set_actor(&mut self, v: u32) {
        self.actor = ::std::option::Option::Some(v);
    }

    pub fn get_actor(&self) -> u32 {
        self.actor.unwrap_or(0)
    }

    fn get_actor_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.actor
    }

    fn mut_actor_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.actor
    }

    // optional string name = 3;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }

    // optional uint32 user_id = 4;

    pub fn clear_user_id(&mut self) {
        self.user_id = ::std::option::Option::None;
    }

    pub fn has_user_id(&self) -> bool {
        self.user_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_user_id(&mut self, v: u32) {
        self.user_id = ::std::option::Option::Some(v);
    }

    pub fn get_user_id(&self) -> u32 {
        self.user_id.unwrap_or(0)
    }

    fn get_user_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.user_id
    }

    fn mut_user_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.user_id
    }

    // optional uint32 channel_id = 5;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional bool mute = 6;

    pub fn clear_mute(&mut self) {
        self.mute = ::std::option::Option::None;
    }

    pub fn has_mute(&self) -> bool {
        self.mute.is_some()
    }

    // Param is passed by value, moved
    pub fn set_mute(&mut self, v: bool) {
        self.mute = ::std::option::Option::Some(v);
    }

    pub fn get_mute(&self) -> bool {
        self.mute.unwrap_or(false)
    }

    fn get_mute_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.mute
    }

    fn mut_mute_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.mute
    }

    // optional bool deaf = 7;

    pub fn clear_deaf(&mut self) {
        self.deaf = ::std::option::Option::None;
    }

    pub fn has_deaf(&self) -> bool {
        self.deaf.is_some()
    }

    // Param is passed by value, moved
    pub fn set_deaf(&mut self, v: bool) {
        self.deaf = ::std::option::Option::Some(v);
    }

    pub fn get_deaf(&self) -> bool {
        self.deaf.unwrap_or(false)
    }

    fn get_deaf_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.deaf
    }

    fn mut_deaf_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.deaf
    }

    // optional bool suppress = 8;

    pub fn clear_suppress(&mut self) {
        self.suppress = ::std::option::Option::None;
    }

    pub fn has_suppress(&self) -> bool {
        self.suppress.is_some()
    }

    // Param is passed by value, moved
    pub fn set_suppress(&mut self, v: bool) {
        self.suppress = ::std::option::Option::Some(v);
    }

    pub fn get_suppress(&self) -> bool {
        self.suppress.unwrap_or(false)
    }

    fn get_suppress_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.suppress
    }

    fn mut_suppress_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.suppress
    }

    // optional bool self_mute = 9;

    pub fn clear_self_mute(&mut self) {
        self.self_mute = ::std::option::Option::None;
    }

    pub fn has_self_mute(&self) -> bool {
        self.self_mute.is_some()
    }

    // Param is passed by value, moved
    pub fn set_self_mute(&mut self, v: bool) {
        self.self_mute = ::std::option::Option::Some(v);
    }

    pub fn get_self_mute(&self) -> bool {
        self.self_mute.unwrap_or(false)
    }

    fn get_self_mute_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.self_mute
    }

    fn mut_self_mute_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.self_mute
    }

    // optional bool self_deaf = 10;

    pub fn clear_self_deaf(&mut self) {
        self.self_deaf = ::std::option::Option::None;
    }

    pub fn has_self_deaf(&self) -> bool {
        self.self_deaf.is_some()
    }

    // Param is passed by value, moved
    pub fn set_self_deaf(&mut self, v: bool) {
        self.self_deaf = ::std::option::Option::Some(v);
    }

    pub fn get_self_deaf(&self) -> bool {
        self.self_deaf.unwrap_or(false)
    }

    fn get_self_deaf_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.self_deaf
    }

    fn mut_self_deaf_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.self_deaf
    }

    // optional bytes texture = 11;

    pub fn clear_texture(&mut self) {
        self.texture.clear();
    }

    pub fn has_texture(&self) -> bool {
        self.texture.is_some()
    }

    // Param is passed by value, moved
    pub fn set_texture(&mut self, v: ::std::vec::Vec<u8>) {
        self.texture = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_texture(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.texture.is_none() {
            self.texture.set_default();
        }
        self.texture.as_mut().unwrap()
    }

    // Take field
    pub fn take_texture(&mut self) -> ::std::vec::Vec<u8> {
        self.texture.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_texture(&self) -> &[u8] {
        match self.texture.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_texture_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.texture
    }

    fn mut_texture_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.texture
    }

    // optional bytes plugin_context = 12;

    pub fn clear_plugin_context(&mut self) {
        self.plugin_context.clear();
    }

    pub fn has_plugin_context(&self) -> bool {
        self.plugin_context.is_some()
    }

    // Param is passed by value, moved
    pub fn set_plugin_context(&mut self, v: ::std::vec::Vec<u8>) {
        self.plugin_context = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_plugin_context(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.plugin_context.is_none() {
            self.plugin_context.set_default();
        }
        self.plugin_context.as_mut().unwrap()
    }

    // Take field
    pub fn take_plugin_context(&mut self) -> ::std::vec::Vec<u8> {
        self.plugin_context.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_plugin_context(&self) -> &[u8] {
        match self.plugin_context.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_plugin_context_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.plugin_context
    }

    fn mut_plugin_context_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.plugin_context
    }

    // optional string plugin_identity = 13;

    pub fn clear_plugin_identity(&mut self) {
        self.plugin_identity.clear();
    }

    pub fn has_plugin_identity(&self) -> bool {
        self.plugin_identity.is_some()
    }

    // Param is passed by value, moved
    pub fn set_plugin_identity(&mut self, v: ::std::string::String) {
        self.plugin_identity = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_plugin_identity(&mut self) -> &mut ::std::string::String {
        if self.plugin_identity.is_none() {
            self.plugin_identity.set_default();
        }
        self.plugin_identity.as_mut().unwrap()
    }

    // Take field
    pub fn take_plugin_identity(&mut self) -> ::std::string::String {
        self.plugin_identity.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_plugin_identity(&self) -> &str {
        match self.plugin_identity.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_plugin_identity_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.plugin_identity
    }

    fn mut_plugin_identity_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.plugin_identity
    }

    // optional string comment = 14;

    pub fn clear_comment(&mut self) {
        self.comment.clear();
    }

    pub fn has_comment(&self) -> bool {
        self.comment.is_some()
    }

    // Param is passed by value, moved
    pub fn set_comment(&mut self, v: ::std::string::String) {
        self.comment = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_comment(&mut self) -> &mut ::std::string::String {
        if self.comment.is_none() {
            self.comment.set_default();
        }
        self.comment.as_mut().unwrap()
    }

    // Take field
    pub fn take_comment(&mut self) -> ::std::string::String {
        self.comment.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_comment(&self) -> &str {
        match self.comment.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_comment_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.comment
    }

    fn mut_comment_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.comment
    }

    // optional string hash = 15;

    pub fn clear_hash(&mut self) {
        self.hash.clear();
    }

    pub fn has_hash(&self) -> bool {
        self.hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_hash(&mut self, v: ::std::string::String) {
        self.hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_hash(&mut self) -> &mut ::std::string::String {
        if self.hash.is_none() {
            self.hash.set_default();
        }
        self.hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_hash(&mut self) -> ::std::string::String {
        self.hash.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_hash(&self) -> &str {
        match self.hash.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_hash_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.hash
    }

    fn mut_hash_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.hash
    }

    // optional bytes comment_hash = 16;

    pub fn clear_comment_hash(&mut self) {
        self.comment_hash.clear();
    }

    pub fn has_comment_hash(&self) -> bool {
        self.comment_hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_comment_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.comment_hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_comment_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.comment_hash.is_none() {
            self.comment_hash.set_default();
        }
        self.comment_hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_comment_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.comment_hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_comment_hash(&self) -> &[u8] {
        match self.comment_hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_comment_hash_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.comment_hash
    }

    fn mut_comment_hash_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.comment_hash
    }

    // optional bytes texture_hash = 17;

    pub fn clear_texture_hash(&mut self) {
        self.texture_hash.clear();
    }

    pub fn has_texture_hash(&self) -> bool {
        self.texture_hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_texture_hash(&mut self, v: ::std::vec::Vec<u8>) {
        self.texture_hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_texture_hash(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.texture_hash.is_none() {
            self.texture_hash.set_default();
        }
        self.texture_hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_texture_hash(&mut self) -> ::std::vec::Vec<u8> {
        self.texture_hash.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_texture_hash(&self) -> &[u8] {
        match self.texture_hash.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_texture_hash_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.texture_hash
    }

    fn mut_texture_hash_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.texture_hash
    }

    // optional bool priority_speaker = 18;

    pub fn clear_priority_speaker(&mut self) {
        self.priority_speaker = ::std::option::Option::None;
    }

    pub fn has_priority_speaker(&self) -> bool {
        self.priority_speaker.is_some()
    }

    // Param is passed by value, moved
    pub fn set_priority_speaker(&mut self, v: bool) {
        self.priority_speaker = ::std::option::Option::Some(v);
    }

    pub fn get_priority_speaker(&self) -> bool {
        self.priority_speaker.unwrap_or(false)
    }

    fn get_priority_speaker_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.priority_speaker
    }

    fn mut_priority_speaker_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.priority_speaker
    }

    // optional bool recording = 19;

    pub fn clear_recording(&mut self) {
        self.recording = ::std::option::Option::None;
    }

    pub fn has_recording(&self) -> bool {
        self.recording.is_some()
    }

    // Param is passed by value, moved
    pub fn set_recording(&mut self, v: bool) {
        self.recording = ::std::option::Option::Some(v);
    }

    pub fn get_recording(&self) -> bool {
        self.recording.unwrap_or(false)
    }

    fn get_recording_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.recording
    }

    fn mut_recording_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.recording
    }
}

impl ::protobuf::Message for UserState {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.actor = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.user_id = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.mute = ::std::option::Option::Some(tmp);
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.deaf = ::std::option::Option::Some(tmp);
                },
                8 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.suppress = ::std::option::Option::Some(tmp);
                },
                9 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.self_mute = ::std::option::Option::Some(tmp);
                },
                10 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.self_deaf = ::std::option::Option::Some(tmp);
                },
                11 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.texture)?;
                },
                12 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.plugin_context)?;
                },
                13 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.plugin_identity)?;
                },
                14 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.comment)?;
                },
                15 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.hash)?;
                },
                16 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.comment_hash)?;
                },
                17 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.texture_hash)?;
                },
                18 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.priority_speaker = ::std::option::Option::Some(tmp);
                },
                19 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.recording = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.actor {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.user_id {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.mute {
            my_size += 2;
        }
        if let Some(v) = self.deaf {
            my_size += 2;
        }
        if let Some(v) = self.suppress {
            my_size += 2;
        }
        if let Some(v) = self.self_mute {
            my_size += 2;
        }
        if let Some(v) = self.self_deaf {
            my_size += 2;
        }
        if let Some(ref v) = self.texture.as_ref() {
            my_size += ::protobuf::rt::bytes_size(11, &v);
        }
        if let Some(ref v) = self.plugin_context.as_ref() {
            my_size += ::protobuf::rt::bytes_size(12, &v);
        }
        if let Some(ref v) = self.plugin_identity.as_ref() {
            my_size += ::protobuf::rt::string_size(13, &v);
        }
        if let Some(ref v) = self.comment.as_ref() {
            my_size += ::protobuf::rt::string_size(14, &v);
        }
        if let Some(ref v) = self.hash.as_ref() {
            my_size += ::protobuf::rt::string_size(15, &v);
        }
        if let Some(ref v) = self.comment_hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(16, &v);
        }
        if let Some(ref v) = self.texture_hash.as_ref() {
            my_size += ::protobuf::rt::bytes_size(17, &v);
        }
        if let Some(v) = self.priority_speaker {
            my_size += 3;
        }
        if let Some(v) = self.recording {
            my_size += 3;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.session {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.actor {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(v) = self.user_id {
            os.write_uint32(4, v)?;
        }
        if let Some(v) = self.channel_id {
            os.write_uint32(5, v)?;
        }
        if let Some(v) = self.mute {
            os.write_bool(6, v)?;
        }
        if let Some(v) = self.deaf {
            os.write_bool(7, v)?;
        }
        if let Some(v) = self.suppress {
            os.write_bool(8, v)?;
        }
        if let Some(v) = self.self_mute {
            os.write_bool(9, v)?;
        }
        if let Some(v) = self.self_deaf {
            os.write_bool(10, v)?;
        }
        if let Some(ref v) = self.texture.as_ref() {
            os.write_bytes(11, &v)?;
        }
        if let Some(ref v) = self.plugin_context.as_ref() {
            os.write_bytes(12, &v)?;
        }
        if let Some(ref v) = self.plugin_identity.as_ref() {
            os.write_string(13, &v)?;
        }
        if let Some(ref v) = self.comment.as_ref() {
            os.write_string(14, &v)?;
        }
        if let Some(ref v) = self.hash.as_ref() {
            os.write_string(15, &v)?;
        }
        if let Some(ref v) = self.comment_hash.as_ref() {
            os.write_bytes(16, &v)?;
        }
        if let Some(ref v) = self.texture_hash.as_ref() {
            os.write_bytes(17, &v)?;
        }
        if let Some(v) = self.priority_speaker {
            os.write_bool(18, v)?;
        }
        if let Some(v) = self.recording {
            os.write_bool(19, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserState {
    fn new() -> UserState {
        UserState::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserState>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    UserState::get_session_for_reflect,
                    UserState::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "actor",
                    UserState::get_actor_for_reflect,
                    UserState::mut_actor_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    UserState::get_name_for_reflect,
                    UserState::mut_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "user_id",
                    UserState::get_user_id_for_reflect,
                    UserState::mut_user_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    UserState::get_channel_id_for_reflect,
                    UserState::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "mute",
                    UserState::get_mute_for_reflect,
                    UserState::mut_mute_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "deaf",
                    UserState::get_deaf_for_reflect,
                    UserState::mut_deaf_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "suppress",
                    UserState::get_suppress_for_reflect,
                    UserState::mut_suppress_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "self_mute",
                    UserState::get_self_mute_for_reflect,
                    UserState::mut_self_mute_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "self_deaf",
                    UserState::get_self_deaf_for_reflect,
                    UserState::mut_self_deaf_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "texture",
                    UserState::get_texture_for_reflect,
                    UserState::mut_texture_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "plugin_context",
                    UserState::get_plugin_context_for_reflect,
                    UserState::mut_plugin_context_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "plugin_identity",
                    UserState::get_plugin_identity_for_reflect,
                    UserState::mut_plugin_identity_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "comment",
                    UserState::get_comment_for_reflect,
                    UserState::mut_comment_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "hash",
                    UserState::get_hash_for_reflect,
                    UserState::mut_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "comment_hash",
                    UserState::get_comment_hash_for_reflect,
                    UserState::mut_comment_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "texture_hash",
                    UserState::get_texture_hash_for_reflect,
                    UserState::mut_texture_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "priority_speaker",
                    UserState::get_priority_speaker_for_reflect,
                    UserState::mut_priority_speaker_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "recording",
                    UserState::get_recording_for_reflect,
                    UserState::mut_recording_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserState>(
                    "UserState",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserState {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_actor();
        self.clear_name();
        self.clear_user_id();
        self.clear_channel_id();
        self.clear_mute();
        self.clear_deaf();
        self.clear_suppress();
        self.clear_self_mute();
        self.clear_self_deaf();
        self.clear_texture();
        self.clear_plugin_context();
        self.clear_plugin_identity();
        self.clear_comment();
        self.clear_hash();
        self.clear_comment_hash();
        self.clear_texture_hash();
        self.clear_priority_speaker();
        self.clear_recording();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserState {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct BanList {
    // message fields
    bans: ::protobuf::RepeatedField<BanList_BanEntry>,
    query: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for BanList {}

impl BanList {
    pub fn new() -> BanList {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static BanList {
        static mut instance: ::protobuf::lazy::Lazy<BanList> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const BanList,
        };
        unsafe {
            instance.get(BanList::new)
        }
    }

    // repeated .MumbleProto.BanList.BanEntry bans = 1;

    pub fn clear_bans(&mut self) {
        self.bans.clear();
    }

    // Param is passed by value, moved
    pub fn set_bans(&mut self, v: ::protobuf::RepeatedField<BanList_BanEntry>) {
        self.bans = v;
    }

    // Mutable pointer to the field.
    pub fn mut_bans(&mut self) -> &mut ::protobuf::RepeatedField<BanList_BanEntry> {
        &mut self.bans
    }

    // Take field
    pub fn take_bans(&mut self) -> ::protobuf::RepeatedField<BanList_BanEntry> {
        ::std::mem::replace(&mut self.bans, ::protobuf::RepeatedField::new())
    }

    pub fn get_bans(&self) -> &[BanList_BanEntry] {
        &self.bans
    }

    fn get_bans_for_reflect(&self) -> &::protobuf::RepeatedField<BanList_BanEntry> {
        &self.bans
    }

    fn mut_bans_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<BanList_BanEntry> {
        &mut self.bans
    }

    // optional bool query = 2;

    pub fn clear_query(&mut self) {
        self.query = ::std::option::Option::None;
    }

    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }

    // Param is passed by value, moved
    pub fn set_query(&mut self, v: bool) {
        self.query = ::std::option::Option::Some(v);
    }

    pub fn get_query(&self) -> bool {
        self.query.unwrap_or(false)
    }

    fn get_query_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.query
    }

    fn mut_query_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.query
    }
}

impl ::protobuf::Message for BanList {
    fn is_initialized(&self) -> bool {
        for v in &self.bans {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.bans)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.query = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.bans {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        if let Some(v) = self.query {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.bans {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        if let Some(v) = self.query {
            os.write_bool(2, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for BanList {
    fn new() -> BanList {
        BanList::new()
    }

    fn descriptor_static(_: ::std::option::Option<BanList>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<BanList_BanEntry>>(
                    "bans",
                    BanList::get_bans_for_reflect,
                    BanList::mut_bans_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "query",
                    BanList::get_query_for_reflect,
                    BanList::mut_query_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<BanList>(
                    "BanList",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for BanList {
    fn clear(&mut self) {
        self.clear_bans();
        self.clear_query();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for BanList {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BanList {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct BanList_BanEntry {
    // message fields
    address: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    mask: ::std::option::Option<u32>,
    name: ::protobuf::SingularField<::std::string::String>,
    hash: ::protobuf::SingularField<::std::string::String>,
    reason: ::protobuf::SingularField<::std::string::String>,
    start: ::protobuf::SingularField<::std::string::String>,
    duration: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for BanList_BanEntry {}

impl BanList_BanEntry {
    pub fn new() -> BanList_BanEntry {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static BanList_BanEntry {
        static mut instance: ::protobuf::lazy::Lazy<BanList_BanEntry> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const BanList_BanEntry,
        };
        unsafe {
            instance.get(BanList_BanEntry::new)
        }
    }

    // required bytes address = 1;

    pub fn clear_address(&mut self) {
        self.address.clear();
    }

    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    // Param is passed by value, moved
    pub fn set_address(&mut self, v: ::std::vec::Vec<u8>) {
        self.address = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_address(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.address.is_none() {
            self.address.set_default();
        }
        self.address.as_mut().unwrap()
    }

    // Take field
    pub fn take_address(&mut self) -> ::std::vec::Vec<u8> {
        self.address.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_address(&self) -> &[u8] {
        match self.address.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_address_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.address
    }

    fn mut_address_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.address
    }

    // required uint32 mask = 2;

    pub fn clear_mask(&mut self) {
        self.mask = ::std::option::Option::None;
    }

    pub fn has_mask(&self) -> bool {
        self.mask.is_some()
    }

    // Param is passed by value, moved
    pub fn set_mask(&mut self, v: u32) {
        self.mask = ::std::option::Option::Some(v);
    }

    pub fn get_mask(&self) -> u32 {
        self.mask.unwrap_or(0)
    }

    fn get_mask_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.mask
    }

    fn mut_mask_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.mask
    }

    // optional string name = 3;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }

    // optional string hash = 4;

    pub fn clear_hash(&mut self) {
        self.hash.clear();
    }

    pub fn has_hash(&self) -> bool {
        self.hash.is_some()
    }

    // Param is passed by value, moved
    pub fn set_hash(&mut self, v: ::std::string::String) {
        self.hash = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_hash(&mut self) -> &mut ::std::string::String {
        if self.hash.is_none() {
            self.hash.set_default();
        }
        self.hash.as_mut().unwrap()
    }

    // Take field
    pub fn take_hash(&mut self) -> ::std::string::String {
        self.hash.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_hash(&self) -> &str {
        match self.hash.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_hash_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.hash
    }

    fn mut_hash_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.hash
    }

    // optional string reason = 5;

    pub fn clear_reason(&mut self) {
        self.reason.clear();
    }

    pub fn has_reason(&self) -> bool {
        self.reason.is_some()
    }

    // Param is passed by value, moved
    pub fn set_reason(&mut self, v: ::std::string::String) {
        self.reason = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_reason(&mut self) -> &mut ::std::string::String {
        if self.reason.is_none() {
            self.reason.set_default();
        }
        self.reason.as_mut().unwrap()
    }

    // Take field
    pub fn take_reason(&mut self) -> ::std::string::String {
        self.reason.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_reason(&self) -> &str {
        match self.reason.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_reason_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.reason
    }

    fn mut_reason_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.reason
    }

    // optional string start = 6;

    pub fn clear_start(&mut self) {
        self.start.clear();
    }

    pub fn has_start(&self) -> bool {
        self.start.is_some()
    }

    // Param is passed by value, moved
    pub fn set_start(&mut self, v: ::std::string::String) {
        self.start = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_start(&mut self) -> &mut ::std::string::String {
        if self.start.is_none() {
            self.start.set_default();
        }
        self.start.as_mut().unwrap()
    }

    // Take field
    pub fn take_start(&mut self) -> ::std::string::String {
        self.start.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_start(&self) -> &str {
        match self.start.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_start_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.start
    }

    fn mut_start_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.start
    }

    // optional uint32 duration = 7;

    pub fn clear_duration(&mut self) {
        self.duration = ::std::option::Option::None;
    }

    pub fn has_duration(&self) -> bool {
        self.duration.is_some()
    }

    // Param is passed by value, moved
    pub fn set_duration(&mut self, v: u32) {
        self.duration = ::std::option::Option::Some(v);
    }

    pub fn get_duration(&self) -> u32 {
        self.duration.unwrap_or(0)
    }

    fn get_duration_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.duration
    }

    fn mut_duration_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.duration
    }
}

impl ::protobuf::Message for BanList_BanEntry {
    fn is_initialized(&self) -> bool {
        if self.address.is_none() {
            return false;
        }
        if self.mask.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.address)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.mask = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                4 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.hash)?;
                },
                5 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.reason)?;
                },
                6 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.start)?;
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.duration = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.address.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        if let Some(v) = self.mask {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(ref v) = self.hash.as_ref() {
            my_size += ::protobuf::rt::string_size(4, &v);
        }
        if let Some(ref v) = self.reason.as_ref() {
            my_size += ::protobuf::rt::string_size(5, &v);
        }
        if let Some(ref v) = self.start.as_ref() {
            my_size += ::protobuf::rt::string_size(6, &v);
        }
        if let Some(v) = self.duration {
            my_size += ::protobuf::rt::value_size(7, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.address.as_ref() {
            os.write_bytes(1, &v)?;
        }
        if let Some(v) = self.mask {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(ref v) = self.hash.as_ref() {
            os.write_string(4, &v)?;
        }
        if let Some(ref v) = self.reason.as_ref() {
            os.write_string(5, &v)?;
        }
        if let Some(ref v) = self.start.as_ref() {
            os.write_string(6, &v)?;
        }
        if let Some(v) = self.duration {
            os.write_uint32(7, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for BanList_BanEntry {
    fn new() -> BanList_BanEntry {
        BanList_BanEntry::new()
    }

    fn descriptor_static(_: ::std::option::Option<BanList_BanEntry>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "address",
                    BanList_BanEntry::get_address_for_reflect,
                    BanList_BanEntry::mut_address_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "mask",
                    BanList_BanEntry::get_mask_for_reflect,
                    BanList_BanEntry::mut_mask_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    BanList_BanEntry::get_name_for_reflect,
                    BanList_BanEntry::mut_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "hash",
                    BanList_BanEntry::get_hash_for_reflect,
                    BanList_BanEntry::mut_hash_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "reason",
                    BanList_BanEntry::get_reason_for_reflect,
                    BanList_BanEntry::mut_reason_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "start",
                    BanList_BanEntry::get_start_for_reflect,
                    BanList_BanEntry::mut_start_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "duration",
                    BanList_BanEntry::get_duration_for_reflect,
                    BanList_BanEntry::mut_duration_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<BanList_BanEntry>(
                    "BanList_BanEntry",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for BanList_BanEntry {
    fn clear(&mut self) {
        self.clear_address();
        self.clear_mask();
        self.clear_name();
        self.clear_hash();
        self.clear_reason();
        self.clear_start();
        self.clear_duration();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for BanList_BanEntry {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for BanList_BanEntry {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct TextMessage {
    // message fields
    actor: ::std::option::Option<u32>,
    session: ::std::vec::Vec<u32>,
    channel_id: ::std::vec::Vec<u32>,
    tree_id: ::std::vec::Vec<u32>,
    message: ::protobuf::SingularField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for TextMessage {}

impl TextMessage {
    pub fn new() -> TextMessage {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static TextMessage {
        static mut instance: ::protobuf::lazy::Lazy<TextMessage> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const TextMessage,
        };
        unsafe {
            instance.get(TextMessage::new)
        }
    }

    // optional uint32 actor = 1;

    pub fn clear_actor(&mut self) {
        self.actor = ::std::option::Option::None;
    }

    pub fn has_actor(&self) -> bool {
        self.actor.is_some()
    }

    // Param is passed by value, moved
    pub fn set_actor(&mut self, v: u32) {
        self.actor = ::std::option::Option::Some(v);
    }

    pub fn get_actor(&self) -> u32 {
        self.actor.unwrap_or(0)
    }

    fn get_actor_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.actor
    }

    fn mut_actor_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.actor
    }

    // repeated uint32 session = 2;

    pub fn clear_session(&mut self) {
        self.session.clear();
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: ::std::vec::Vec<u32>) {
        self.session = v;
    }

    // Mutable pointer to the field.
    pub fn mut_session(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session
    }

    // Take field
    pub fn take_session(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.session, ::std::vec::Vec::new())
    }

    pub fn get_session(&self) -> &[u32] {
        &self.session
    }

    fn get_session_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session
    }

    // repeated uint32 channel_id = 3;

    pub fn clear_channel_id(&mut self) {
        self.channel_id.clear();
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: ::std::vec::Vec<u32>) {
        self.channel_id = v;
    }

    // Mutable pointer to the field.
    pub fn mut_channel_id(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.channel_id
    }

    // Take field
    pub fn take_channel_id(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.channel_id, ::std::vec::Vec::new())
    }

    pub fn get_channel_id(&self) -> &[u32] {
        &self.channel_id
    }

    fn get_channel_id_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.channel_id
    }

    // repeated uint32 tree_id = 4;

    pub fn clear_tree_id(&mut self) {
        self.tree_id.clear();
    }

    // Param is passed by value, moved
    pub fn set_tree_id(&mut self, v: ::std::vec::Vec<u32>) {
        self.tree_id = v;
    }

    // Mutable pointer to the field.
    pub fn mut_tree_id(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.tree_id
    }

    // Take field
    pub fn take_tree_id(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.tree_id, ::std::vec::Vec::new())
    }

    pub fn get_tree_id(&self) -> &[u32] {
        &self.tree_id
    }

    fn get_tree_id_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.tree_id
    }

    fn mut_tree_id_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.tree_id
    }

    // required string message = 5;

    pub fn clear_message(&mut self) {
        self.message.clear();
    }

    pub fn has_message(&self) -> bool {
        self.message.is_some()
    }

    // Param is passed by value, moved
    pub fn set_message(&mut self, v: ::std::string::String) {
        self.message = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_message(&mut self) -> &mut ::std::string::String {
        if self.message.is_none() {
            self.message.set_default();
        }
        self.message.as_mut().unwrap()
    }

    // Take field
    pub fn take_message(&mut self) -> ::std::string::String {
        self.message.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_message(&self) -> &str {
        match self.message.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_message_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.message
    }

    fn mut_message_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.message
    }
}

impl ::protobuf::Message for TextMessage {
    fn is_initialized(&self) -> bool {
        if self.message.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.actor = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.session)?;
                },
                3 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.channel_id)?;
                },
                4 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.tree_id)?;
                },
                5 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.message)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.actor {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        for value in &self.session {
            my_size += ::protobuf::rt::value_size(2, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.channel_id {
            my_size += ::protobuf::rt::value_size(3, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.tree_id {
            my_size += ::protobuf::rt::value_size(4, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(ref v) = self.message.as_ref() {
            my_size += ::protobuf::rt::string_size(5, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.actor {
            os.write_uint32(1, v)?;
        }
        for v in &self.session {
            os.write_uint32(2, *v)?;
        };
        for v in &self.channel_id {
            os.write_uint32(3, *v)?;
        };
        for v in &self.tree_id {
            os.write_uint32(4, *v)?;
        };
        if let Some(ref v) = self.message.as_ref() {
            os.write_string(5, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for TextMessage {
    fn new() -> TextMessage {
        TextMessage::new()
    }

    fn descriptor_static(_: ::std::option::Option<TextMessage>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "actor",
                    TextMessage::get_actor_for_reflect,
                    TextMessage::mut_actor_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    TextMessage::get_session_for_reflect,
                    TextMessage::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    TextMessage::get_channel_id_for_reflect,
                    TextMessage::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tree_id",
                    TextMessage::get_tree_id_for_reflect,
                    TextMessage::mut_tree_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "message",
                    TextMessage::get_message_for_reflect,
                    TextMessage::mut_message_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<TextMessage>(
                    "TextMessage",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for TextMessage {
    fn clear(&mut self) {
        self.clear_actor();
        self.clear_session();
        self.clear_channel_id();
        self.clear_tree_id();
        self.clear_message();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for TextMessage {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for TextMessage {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct PermissionDenied {
    // message fields
    permission: ::std::option::Option<u32>,
    channel_id: ::std::option::Option<u32>,
    session: ::std::option::Option<u32>,
    reason: ::protobuf::SingularField<::std::string::String>,
    field_type: ::std::option::Option<PermissionDenied_DenyType>,
    name: ::protobuf::SingularField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for PermissionDenied {}

impl PermissionDenied {
    pub fn new() -> PermissionDenied {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static PermissionDenied {
        static mut instance: ::protobuf::lazy::Lazy<PermissionDenied> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const PermissionDenied,
        };
        unsafe {
            instance.get(PermissionDenied::new)
        }
    }

    // optional uint32 permission = 1;

    pub fn clear_permission(&mut self) {
        self.permission = ::std::option::Option::None;
    }

    pub fn has_permission(&self) -> bool {
        self.permission.is_some()
    }

    // Param is passed by value, moved
    pub fn set_permission(&mut self, v: u32) {
        self.permission = ::std::option::Option::Some(v);
    }

    pub fn get_permission(&self) -> u32 {
        self.permission.unwrap_or(0)
    }

    fn get_permission_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.permission
    }

    fn mut_permission_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.permission
    }

    // optional uint32 channel_id = 2;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional uint32 session = 3;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional string reason = 4;

    pub fn clear_reason(&mut self) {
        self.reason.clear();
    }

    pub fn has_reason(&self) -> bool {
        self.reason.is_some()
    }

    // Param is passed by value, moved
    pub fn set_reason(&mut self, v: ::std::string::String) {
        self.reason = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_reason(&mut self) -> &mut ::std::string::String {
        if self.reason.is_none() {
            self.reason.set_default();
        }
        self.reason.as_mut().unwrap()
    }

    // Take field
    pub fn take_reason(&mut self) -> ::std::string::String {
        self.reason.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_reason(&self) -> &str {
        match self.reason.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_reason_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.reason
    }

    fn mut_reason_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.reason
    }

    // optional .MumbleProto.PermissionDenied.DenyType type = 5;

    pub fn clear_field_type(&mut self) {
        self.field_type = ::std::option::Option::None;
    }

    pub fn has_field_type(&self) -> bool {
        self.field_type.is_some()
    }

    // Param is passed by value, moved
    pub fn set_field_type(&mut self, v: PermissionDenied_DenyType) {
        self.field_type = ::std::option::Option::Some(v);
    }

    pub fn get_field_type(&self) -> PermissionDenied_DenyType {
        self.field_type.unwrap_or(PermissionDenied_DenyType::Text)
    }

    fn get_field_type_for_reflect(&self) -> &::std::option::Option<PermissionDenied_DenyType> {
        &self.field_type
    }

    fn mut_field_type_for_reflect(&mut self) -> &mut ::std::option::Option<PermissionDenied_DenyType> {
        &mut self.field_type
    }

    // optional string name = 6;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }
}

impl ::protobuf::Message for PermissionDenied {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.permission = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                4 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.reason)?;
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.field_type = ::std::option::Option::Some(tmp);
                },
                6 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.permission {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(3, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.reason.as_ref() {
            my_size += ::protobuf::rt::string_size(4, &v);
        }
        if let Some(v) = self.field_type {
            my_size += ::protobuf::rt::enum_size(5, v);
        }
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(6, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.permission {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.channel_id {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.session {
            os.write_uint32(3, v)?;
        }
        if let Some(ref v) = self.reason.as_ref() {
            os.write_string(4, &v)?;
        }
        if let Some(v) = self.field_type {
            os.write_enum(5, v.value())?;
        }
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(6, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for PermissionDenied {
    fn new() -> PermissionDenied {
        PermissionDenied::new()
    }

    fn descriptor_static(_: ::std::option::Option<PermissionDenied>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "permission",
                    PermissionDenied::get_permission_for_reflect,
                    PermissionDenied::mut_permission_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    PermissionDenied::get_channel_id_for_reflect,
                    PermissionDenied::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    PermissionDenied::get_session_for_reflect,
                    PermissionDenied::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "reason",
                    PermissionDenied::get_reason_for_reflect,
                    PermissionDenied::mut_reason_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<PermissionDenied_DenyType>>(
                    "type",
                    PermissionDenied::get_field_type_for_reflect,
                    PermissionDenied::mut_field_type_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    PermissionDenied::get_name_for_reflect,
                    PermissionDenied::mut_name_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<PermissionDenied>(
                    "PermissionDenied",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for PermissionDenied {
    fn clear(&mut self) {
        self.clear_permission();
        self.clear_channel_id();
        self.clear_session();
        self.clear_reason();
        self.clear_field_type();
        self.clear_name();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PermissionDenied {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PermissionDenied {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum PermissionDenied_DenyType {
    Text = 0,
    Permission = 1,
    SuperUser = 2,
    ChannelName = 3,
    TextTooLong = 4,
    H9K = 5,
    TemporaryChannel = 6,
    MissingCertificate = 7,
    UserName = 8,
    ChannelFull = 9,
    NestingLimit = 10,
}

impl ::protobuf::ProtobufEnum for PermissionDenied_DenyType {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<PermissionDenied_DenyType> {
        match value {
            0 => ::std::option::Option::Some(PermissionDenied_DenyType::Text),
            1 => ::std::option::Option::Some(PermissionDenied_DenyType::Permission),
            2 => ::std::option::Option::Some(PermissionDenied_DenyType::SuperUser),
            3 => ::std::option::Option::Some(PermissionDenied_DenyType::ChannelName),
            4 => ::std::option::Option::Some(PermissionDenied_DenyType::TextTooLong),
            5 => ::std::option::Option::Some(PermissionDenied_DenyType::H9K),
            6 => ::std::option::Option::Some(PermissionDenied_DenyType::TemporaryChannel),
            7 => ::std::option::Option::Some(PermissionDenied_DenyType::MissingCertificate),
            8 => ::std::option::Option::Some(PermissionDenied_DenyType::UserName),
            9 => ::std::option::Option::Some(PermissionDenied_DenyType::ChannelFull),
            10 => ::std::option::Option::Some(PermissionDenied_DenyType::NestingLimit),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [PermissionDenied_DenyType] = &[
            PermissionDenied_DenyType::Text,
            PermissionDenied_DenyType::Permission,
            PermissionDenied_DenyType::SuperUser,
            PermissionDenied_DenyType::ChannelName,
            PermissionDenied_DenyType::TextTooLong,
            PermissionDenied_DenyType::H9K,
            PermissionDenied_DenyType::TemporaryChannel,
            PermissionDenied_DenyType::MissingCertificate,
            PermissionDenied_DenyType::UserName,
            PermissionDenied_DenyType::ChannelFull,
            PermissionDenied_DenyType::NestingLimit,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<PermissionDenied_DenyType>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("PermissionDenied_DenyType", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for PermissionDenied_DenyType {
}

impl ::protobuf::reflect::ProtobufValue for PermissionDenied_DenyType {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ACL {
    // message fields
    channel_id: ::std::option::Option<u32>,
    inherit_acls: ::std::option::Option<bool>,
    groups: ::protobuf::RepeatedField<ACL_ChanGroup>,
    acls: ::protobuf::RepeatedField<ACL_ChanACL>,
    query: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ACL {}

impl ACL {
    pub fn new() -> ACL {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ACL {
        static mut instance: ::protobuf::lazy::Lazy<ACL> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ACL,
        };
        unsafe {
            instance.get(ACL::new)
        }
    }

    // required uint32 channel_id = 1;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional bool inherit_acls = 2;

    pub fn clear_inherit_acls(&mut self) {
        self.inherit_acls = ::std::option::Option::None;
    }

    pub fn has_inherit_acls(&self) -> bool {
        self.inherit_acls.is_some()
    }

    // Param is passed by value, moved
    pub fn set_inherit_acls(&mut self, v: bool) {
        self.inherit_acls = ::std::option::Option::Some(v);
    }

    pub fn get_inherit_acls(&self) -> bool {
        self.inherit_acls.unwrap_or(true)
    }

    fn get_inherit_acls_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.inherit_acls
    }

    fn mut_inherit_acls_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.inherit_acls
    }

    // repeated .MumbleProto.ACL.ChanGroup groups = 3;

    pub fn clear_groups(&mut self) {
        self.groups.clear();
    }

    // Param is passed by value, moved
    pub fn set_groups(&mut self, v: ::protobuf::RepeatedField<ACL_ChanGroup>) {
        self.groups = v;
    }

    // Mutable pointer to the field.
    pub fn mut_groups(&mut self) -> &mut ::protobuf::RepeatedField<ACL_ChanGroup> {
        &mut self.groups
    }

    // Take field
    pub fn take_groups(&mut self) -> ::protobuf::RepeatedField<ACL_ChanGroup> {
        ::std::mem::replace(&mut self.groups, ::protobuf::RepeatedField::new())
    }

    pub fn get_groups(&self) -> &[ACL_ChanGroup] {
        &self.groups
    }

    fn get_groups_for_reflect(&self) -> &::protobuf::RepeatedField<ACL_ChanGroup> {
        &self.groups
    }

    fn mut_groups_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<ACL_ChanGroup> {
        &mut self.groups
    }

    // repeated .MumbleProto.ACL.ChanACL acls = 4;

    pub fn clear_acls(&mut self) {
        self.acls.clear();
    }

    // Param is passed by value, moved
    pub fn set_acls(&mut self, v: ::protobuf::RepeatedField<ACL_ChanACL>) {
        self.acls = v;
    }

    // Mutable pointer to the field.
    pub fn mut_acls(&mut self) -> &mut ::protobuf::RepeatedField<ACL_ChanACL> {
        &mut self.acls
    }

    // Take field
    pub fn take_acls(&mut self) -> ::protobuf::RepeatedField<ACL_ChanACL> {
        ::std::mem::replace(&mut self.acls, ::protobuf::RepeatedField::new())
    }

    pub fn get_acls(&self) -> &[ACL_ChanACL] {
        &self.acls
    }

    fn get_acls_for_reflect(&self) -> &::protobuf::RepeatedField<ACL_ChanACL> {
        &self.acls
    }

    fn mut_acls_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<ACL_ChanACL> {
        &mut self.acls
    }

    // optional bool query = 5;

    pub fn clear_query(&mut self) {
        self.query = ::std::option::Option::None;
    }

    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }

    // Param is passed by value, moved
    pub fn set_query(&mut self, v: bool) {
        self.query = ::std::option::Option::Some(v);
    }

    pub fn get_query(&self) -> bool {
        self.query.unwrap_or(false)
    }

    fn get_query_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.query
    }

    fn mut_query_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.query
    }
}

impl ::protobuf::Message for ACL {
    fn is_initialized(&self) -> bool {
        if self.channel_id.is_none() {
            return false;
        }
        for v in &self.groups {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.acls {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.inherit_acls = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.groups)?;
                },
                4 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.acls)?;
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.query = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.inherit_acls {
            my_size += 2;
        }
        for value in &self.groups {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        for value in &self.acls {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        if let Some(v) = self.query {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.channel_id {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.inherit_acls {
            os.write_bool(2, v)?;
        }
        for v in &self.groups {
            os.write_tag(3, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        for v in &self.acls {
            os.write_tag(4, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        if let Some(v) = self.query {
            os.write_bool(5, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ACL {
    fn new() -> ACL {
        ACL::new()
    }

    fn descriptor_static(_: ::std::option::Option<ACL>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    ACL::get_channel_id_for_reflect,
                    ACL::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "inherit_acls",
                    ACL::get_inherit_acls_for_reflect,
                    ACL::mut_inherit_acls_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ACL_ChanGroup>>(
                    "groups",
                    ACL::get_groups_for_reflect,
                    ACL::mut_groups_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<ACL_ChanACL>>(
                    "acls",
                    ACL::get_acls_for_reflect,
                    ACL::mut_acls_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "query",
                    ACL::get_query_for_reflect,
                    ACL::mut_query_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ACL>(
                    "ACL",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ACL {
    fn clear(&mut self) {
        self.clear_channel_id();
        self.clear_inherit_acls();
        self.clear_groups();
        self.clear_acls();
        self.clear_query();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ACL {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ACL {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ACL_ChanGroup {
    // message fields
    name: ::protobuf::SingularField<::std::string::String>,
    inherited: ::std::option::Option<bool>,
    inherit: ::std::option::Option<bool>,
    inheritable: ::std::option::Option<bool>,
    add: ::std::vec::Vec<u32>,
    remove: ::std::vec::Vec<u32>,
    inherited_members: ::std::vec::Vec<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ACL_ChanGroup {}

impl ACL_ChanGroup {
    pub fn new() -> ACL_ChanGroup {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ACL_ChanGroup {
        static mut instance: ::protobuf::lazy::Lazy<ACL_ChanGroup> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ACL_ChanGroup,
        };
        unsafe {
            instance.get(ACL_ChanGroup::new)
        }
    }

    // required string name = 1;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }

    // optional bool inherited = 2;

    pub fn clear_inherited(&mut self) {
        self.inherited = ::std::option::Option::None;
    }

    pub fn has_inherited(&self) -> bool {
        self.inherited.is_some()
    }

    // Param is passed by value, moved
    pub fn set_inherited(&mut self, v: bool) {
        self.inherited = ::std::option::Option::Some(v);
    }

    pub fn get_inherited(&self) -> bool {
        self.inherited.unwrap_or(true)
    }

    fn get_inherited_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.inherited
    }

    fn mut_inherited_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.inherited
    }

    // optional bool inherit = 3;

    pub fn clear_inherit(&mut self) {
        self.inherit = ::std::option::Option::None;
    }

    pub fn has_inherit(&self) -> bool {
        self.inherit.is_some()
    }

    // Param is passed by value, moved
    pub fn set_inherit(&mut self, v: bool) {
        self.inherit = ::std::option::Option::Some(v);
    }

    pub fn get_inherit(&self) -> bool {
        self.inherit.unwrap_or(true)
    }

    fn get_inherit_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.inherit
    }

    fn mut_inherit_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.inherit
    }

    // optional bool inheritable = 4;

    pub fn clear_inheritable(&mut self) {
        self.inheritable = ::std::option::Option::None;
    }

    pub fn has_inheritable(&self) -> bool {
        self.inheritable.is_some()
    }

    // Param is passed by value, moved
    pub fn set_inheritable(&mut self, v: bool) {
        self.inheritable = ::std::option::Option::Some(v);
    }

    pub fn get_inheritable(&self) -> bool {
        self.inheritable.unwrap_or(true)
    }

    fn get_inheritable_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.inheritable
    }

    fn mut_inheritable_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.inheritable
    }

    // repeated uint32 add = 5;

    pub fn clear_add(&mut self) {
        self.add.clear();
    }

    // Param is passed by value, moved
    pub fn set_add(&mut self, v: ::std::vec::Vec<u32>) {
        self.add = v;
    }

    // Mutable pointer to the field.
    pub fn mut_add(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.add
    }

    // Take field
    pub fn take_add(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.add, ::std::vec::Vec::new())
    }

    pub fn get_add(&self) -> &[u32] {
        &self.add
    }

    fn get_add_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.add
    }

    fn mut_add_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.add
    }

    // repeated uint32 remove = 6;

    pub fn clear_remove(&mut self) {
        self.remove.clear();
    }

    // Param is passed by value, moved
    pub fn set_remove(&mut self, v: ::std::vec::Vec<u32>) {
        self.remove = v;
    }

    // Mutable pointer to the field.
    pub fn mut_remove(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.remove
    }

    // Take field
    pub fn take_remove(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.remove, ::std::vec::Vec::new())
    }

    pub fn get_remove(&self) -> &[u32] {
        &self.remove
    }

    fn get_remove_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.remove
    }

    fn mut_remove_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.remove
    }

    // repeated uint32 inherited_members = 7;

    pub fn clear_inherited_members(&mut self) {
        self.inherited_members.clear();
    }

    // Param is passed by value, moved
    pub fn set_inherited_members(&mut self, v: ::std::vec::Vec<u32>) {
        self.inherited_members = v;
    }

    // Mutable pointer to the field.
    pub fn mut_inherited_members(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.inherited_members
    }

    // Take field
    pub fn take_inherited_members(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.inherited_members, ::std::vec::Vec::new())
    }

    pub fn get_inherited_members(&self) -> &[u32] {
        &self.inherited_members
    }

    fn get_inherited_members_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.inherited_members
    }

    fn mut_inherited_members_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.inherited_members
    }
}

impl ::protobuf::Message for ACL_ChanGroup {
    fn is_initialized(&self) -> bool {
        if self.name.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.inherited = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.inherit = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.inheritable = ::std::option::Option::Some(tmp);
                },
                5 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.add)?;
                },
                6 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.remove)?;
                },
                7 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.inherited_members)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(v) = self.inherited {
            my_size += 2;
        }
        if let Some(v) = self.inherit {
            my_size += 2;
        }
        if let Some(v) = self.inheritable {
            my_size += 2;
        }
        for value in &self.add {
            my_size += ::protobuf::rt::value_size(5, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.remove {
            my_size += ::protobuf::rt::value_size(6, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.inherited_members {
            my_size += ::protobuf::rt::value_size(7, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(1, &v)?;
        }
        if let Some(v) = self.inherited {
            os.write_bool(2, v)?;
        }
        if let Some(v) = self.inherit {
            os.write_bool(3, v)?;
        }
        if let Some(v) = self.inheritable {
            os.write_bool(4, v)?;
        }
        for v in &self.add {
            os.write_uint32(5, *v)?;
        };
        for v in &self.remove {
            os.write_uint32(6, *v)?;
        };
        for v in &self.inherited_members {
            os.write_uint32(7, *v)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ACL_ChanGroup {
    fn new() -> ACL_ChanGroup {
        ACL_ChanGroup::new()
    }

    fn descriptor_static(_: ::std::option::Option<ACL_ChanGroup>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    ACL_ChanGroup::get_name_for_reflect,
                    ACL_ChanGroup::mut_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "inherited",
                    ACL_ChanGroup::get_inherited_for_reflect,
                    ACL_ChanGroup::mut_inherited_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "inherit",
                    ACL_ChanGroup::get_inherit_for_reflect,
                    ACL_ChanGroup::mut_inherit_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "inheritable",
                    ACL_ChanGroup::get_inheritable_for_reflect,
                    ACL_ChanGroup::mut_inheritable_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "add",
                    ACL_ChanGroup::get_add_for_reflect,
                    ACL_ChanGroup::mut_add_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "remove",
                    ACL_ChanGroup::get_remove_for_reflect,
                    ACL_ChanGroup::mut_remove_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "inherited_members",
                    ACL_ChanGroup::get_inherited_members_for_reflect,
                    ACL_ChanGroup::mut_inherited_members_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ACL_ChanGroup>(
                    "ACL_ChanGroup",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ACL_ChanGroup {
    fn clear(&mut self) {
        self.clear_name();
        self.clear_inherited();
        self.clear_inherit();
        self.clear_inheritable();
        self.clear_add();
        self.clear_remove();
        self.clear_inherited_members();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ACL_ChanGroup {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ACL_ChanGroup {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ACL_ChanACL {
    // message fields
    apply_here: ::std::option::Option<bool>,
    apply_subs: ::std::option::Option<bool>,
    inherited: ::std::option::Option<bool>,
    user_id: ::std::option::Option<u32>,
    group: ::protobuf::SingularField<::std::string::String>,
    grant: ::std::option::Option<u32>,
    deny: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ACL_ChanACL {}

impl ACL_ChanACL {
    pub fn new() -> ACL_ChanACL {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ACL_ChanACL {
        static mut instance: ::protobuf::lazy::Lazy<ACL_ChanACL> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ACL_ChanACL,
        };
        unsafe {
            instance.get(ACL_ChanACL::new)
        }
    }

    // optional bool apply_here = 1;

    pub fn clear_apply_here(&mut self) {
        self.apply_here = ::std::option::Option::None;
    }

    pub fn has_apply_here(&self) -> bool {
        self.apply_here.is_some()
    }

    // Param is passed by value, moved
    pub fn set_apply_here(&mut self, v: bool) {
        self.apply_here = ::std::option::Option::Some(v);
    }

    pub fn get_apply_here(&self) -> bool {
        self.apply_here.unwrap_or(true)
    }

    fn get_apply_here_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.apply_here
    }

    fn mut_apply_here_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.apply_here
    }

    // optional bool apply_subs = 2;

    pub fn clear_apply_subs(&mut self) {
        self.apply_subs = ::std::option::Option::None;
    }

    pub fn has_apply_subs(&self) -> bool {
        self.apply_subs.is_some()
    }

    // Param is passed by value, moved
    pub fn set_apply_subs(&mut self, v: bool) {
        self.apply_subs = ::std::option::Option::Some(v);
    }

    pub fn get_apply_subs(&self) -> bool {
        self.apply_subs.unwrap_or(true)
    }

    fn get_apply_subs_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.apply_subs
    }

    fn mut_apply_subs_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.apply_subs
    }

    // optional bool inherited = 3;

    pub fn clear_inherited(&mut self) {
        self.inherited = ::std::option::Option::None;
    }

    pub fn has_inherited(&self) -> bool {
        self.inherited.is_some()
    }

    // Param is passed by value, moved
    pub fn set_inherited(&mut self, v: bool) {
        self.inherited = ::std::option::Option::Some(v);
    }

    pub fn get_inherited(&self) -> bool {
        self.inherited.unwrap_or(true)
    }

    fn get_inherited_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.inherited
    }

    fn mut_inherited_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.inherited
    }

    // optional uint32 user_id = 4;

    pub fn clear_user_id(&mut self) {
        self.user_id = ::std::option::Option::None;
    }

    pub fn has_user_id(&self) -> bool {
        self.user_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_user_id(&mut self, v: u32) {
        self.user_id = ::std::option::Option::Some(v);
    }

    pub fn get_user_id(&self) -> u32 {
        self.user_id.unwrap_or(0)
    }

    fn get_user_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.user_id
    }

    fn mut_user_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.user_id
    }

    // optional string group = 5;

    pub fn clear_group(&mut self) {
        self.group.clear();
    }

    pub fn has_group(&self) -> bool {
        self.group.is_some()
    }

    // Param is passed by value, moved
    pub fn set_group(&mut self, v: ::std::string::String) {
        self.group = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_group(&mut self) -> &mut ::std::string::String {
        if self.group.is_none() {
            self.group.set_default();
        }
        self.group.as_mut().unwrap()
    }

    // Take field
    pub fn take_group(&mut self) -> ::std::string::String {
        self.group.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_group(&self) -> &str {
        match self.group.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_group_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.group
    }

    fn mut_group_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.group
    }

    // optional uint32 grant = 6;

    pub fn clear_grant(&mut self) {
        self.grant = ::std::option::Option::None;
    }

    pub fn has_grant(&self) -> bool {
        self.grant.is_some()
    }

    // Param is passed by value, moved
    pub fn set_grant(&mut self, v: u32) {
        self.grant = ::std::option::Option::Some(v);
    }

    pub fn get_grant(&self) -> u32 {
        self.grant.unwrap_or(0)
    }

    fn get_grant_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.grant
    }

    fn mut_grant_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.grant
    }

    // optional uint32 deny = 7;

    pub fn clear_deny(&mut self) {
        self.deny = ::std::option::Option::None;
    }

    pub fn has_deny(&self) -> bool {
        self.deny.is_some()
    }

    // Param is passed by value, moved
    pub fn set_deny(&mut self, v: u32) {
        self.deny = ::std::option::Option::Some(v);
    }

    pub fn get_deny(&self) -> u32 {
        self.deny.unwrap_or(0)
    }

    fn get_deny_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.deny
    }

    fn mut_deny_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.deny
    }
}

impl ::protobuf::Message for ACL_ChanACL {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.apply_here = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.apply_subs = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.inherited = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.user_id = ::std::option::Option::Some(tmp);
                },
                5 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.group)?;
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.grant = ::std::option::Option::Some(tmp);
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.deny = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.apply_here {
            my_size += 2;
        }
        if let Some(v) = self.apply_subs {
            my_size += 2;
        }
        if let Some(v) = self.inherited {
            my_size += 2;
        }
        if let Some(v) = self.user_id {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.group.as_ref() {
            my_size += ::protobuf::rt::string_size(5, &v);
        }
        if let Some(v) = self.grant {
            my_size += ::protobuf::rt::value_size(6, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.deny {
            my_size += ::protobuf::rt::value_size(7, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.apply_here {
            os.write_bool(1, v)?;
        }
        if let Some(v) = self.apply_subs {
            os.write_bool(2, v)?;
        }
        if let Some(v) = self.inherited {
            os.write_bool(3, v)?;
        }
        if let Some(v) = self.user_id {
            os.write_uint32(4, v)?;
        }
        if let Some(ref v) = self.group.as_ref() {
            os.write_string(5, &v)?;
        }
        if let Some(v) = self.grant {
            os.write_uint32(6, v)?;
        }
        if let Some(v) = self.deny {
            os.write_uint32(7, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ACL_ChanACL {
    fn new() -> ACL_ChanACL {
        ACL_ChanACL::new()
    }

    fn descriptor_static(_: ::std::option::Option<ACL_ChanACL>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "apply_here",
                    ACL_ChanACL::get_apply_here_for_reflect,
                    ACL_ChanACL::mut_apply_here_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "apply_subs",
                    ACL_ChanACL::get_apply_subs_for_reflect,
                    ACL_ChanACL::mut_apply_subs_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "inherited",
                    ACL_ChanACL::get_inherited_for_reflect,
                    ACL_ChanACL::mut_inherited_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "user_id",
                    ACL_ChanACL::get_user_id_for_reflect,
                    ACL_ChanACL::mut_user_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "group",
                    ACL_ChanACL::get_group_for_reflect,
                    ACL_ChanACL::mut_group_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "grant",
                    ACL_ChanACL::get_grant_for_reflect,
                    ACL_ChanACL::mut_grant_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "deny",
                    ACL_ChanACL::get_deny_for_reflect,
                    ACL_ChanACL::mut_deny_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ACL_ChanACL>(
                    "ACL_ChanACL",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ACL_ChanACL {
    fn clear(&mut self) {
        self.clear_apply_here();
        self.clear_apply_subs();
        self.clear_inherited();
        self.clear_user_id();
        self.clear_group();
        self.clear_grant();
        self.clear_deny();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ACL_ChanACL {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ACL_ChanACL {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct QueryUsers {
    // message fields
    ids: ::std::vec::Vec<u32>,
    names: ::protobuf::RepeatedField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for QueryUsers {}

impl QueryUsers {
    pub fn new() -> QueryUsers {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static QueryUsers {
        static mut instance: ::protobuf::lazy::Lazy<QueryUsers> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const QueryUsers,
        };
        unsafe {
            instance.get(QueryUsers::new)
        }
    }

    // repeated uint32 ids = 1;

    pub fn clear_ids(&mut self) {
        self.ids.clear();
    }

    // Param is passed by value, moved
    pub fn set_ids(&mut self, v: ::std::vec::Vec<u32>) {
        self.ids = v;
    }

    // Mutable pointer to the field.
    pub fn mut_ids(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.ids
    }

    // Take field
    pub fn take_ids(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.ids, ::std::vec::Vec::new())
    }

    pub fn get_ids(&self) -> &[u32] {
        &self.ids
    }

    fn get_ids_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.ids
    }

    fn mut_ids_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.ids
    }

    // repeated string names = 2;

    pub fn clear_names(&mut self) {
        self.names.clear();
    }

    // Param is passed by value, moved
    pub fn set_names(&mut self, v: ::protobuf::RepeatedField<::std::string::String>) {
        self.names = v;
    }

    // Mutable pointer to the field.
    pub fn mut_names(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.names
    }

    // Take field
    pub fn take_names(&mut self) -> ::protobuf::RepeatedField<::std::string::String> {
        ::std::mem::replace(&mut self.names, ::protobuf::RepeatedField::new())
    }

    pub fn get_names(&self) -> &[::std::string::String] {
        &self.names
    }

    fn get_names_for_reflect(&self) -> &::protobuf::RepeatedField<::std::string::String> {
        &self.names
    }

    fn mut_names_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<::std::string::String> {
        &mut self.names
    }
}

impl ::protobuf::Message for QueryUsers {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.ids)?;
                },
                2 => {
                    ::protobuf::rt::read_repeated_string_into(wire_type, is, &mut self.names)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.ids {
            my_size += ::protobuf::rt::value_size(1, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.names {
            my_size += ::protobuf::rt::string_size(2, &value);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.ids {
            os.write_uint32(1, *v)?;
        };
        for v in &self.names {
            os.write_string(2, &v)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for QueryUsers {
    fn new() -> QueryUsers {
        QueryUsers::new()
    }

    fn descriptor_static(_: ::std::option::Option<QueryUsers>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "ids",
                    QueryUsers::get_ids_for_reflect,
                    QueryUsers::mut_ids_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "names",
                    QueryUsers::get_names_for_reflect,
                    QueryUsers::mut_names_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<QueryUsers>(
                    "QueryUsers",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for QueryUsers {
    fn clear(&mut self) {
        self.clear_ids();
        self.clear_names();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for QueryUsers {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for QueryUsers {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct CryptSetup {
    // message fields
    key: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    client_nonce: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    server_nonce: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CryptSetup {}

impl CryptSetup {
    pub fn new() -> CryptSetup {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CryptSetup {
        static mut instance: ::protobuf::lazy::Lazy<CryptSetup> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CryptSetup,
        };
        unsafe {
            instance.get(CryptSetup::new)
        }
    }

    // optional bytes key = 1;

    pub fn clear_key(&mut self) {
        self.key.clear();
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    // Param is passed by value, moved
    pub fn set_key(&mut self, v: ::std::vec::Vec<u8>) {
        self.key = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_key(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.key.is_none() {
            self.key.set_default();
        }
        self.key.as_mut().unwrap()
    }

    // Take field
    pub fn take_key(&mut self) -> ::std::vec::Vec<u8> {
        self.key.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_key(&self) -> &[u8] {
        match self.key.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_key_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.key
    }

    fn mut_key_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.key
    }

    // optional bytes client_nonce = 2;

    pub fn clear_client_nonce(&mut self) {
        self.client_nonce.clear();
    }

    pub fn has_client_nonce(&self) -> bool {
        self.client_nonce.is_some()
    }

    // Param is passed by value, moved
    pub fn set_client_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.client_nonce = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_client_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.client_nonce.is_none() {
            self.client_nonce.set_default();
        }
        self.client_nonce.as_mut().unwrap()
    }

    // Take field
    pub fn take_client_nonce(&mut self) -> ::std::vec::Vec<u8> {
        self.client_nonce.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_client_nonce(&self) -> &[u8] {
        match self.client_nonce.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_client_nonce_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.client_nonce
    }

    fn mut_client_nonce_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.client_nonce
    }

    // optional bytes server_nonce = 3;

    pub fn clear_server_nonce(&mut self) {
        self.server_nonce.clear();
    }

    pub fn has_server_nonce(&self) -> bool {
        self.server_nonce.is_some()
    }

    // Param is passed by value, moved
    pub fn set_server_nonce(&mut self, v: ::std::vec::Vec<u8>) {
        self.server_nonce = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_server_nonce(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.server_nonce.is_none() {
            self.server_nonce.set_default();
        }
        self.server_nonce.as_mut().unwrap()
    }

    // Take field
    pub fn take_server_nonce(&mut self) -> ::std::vec::Vec<u8> {
        self.server_nonce.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_server_nonce(&self) -> &[u8] {
        match self.server_nonce.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_server_nonce_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.server_nonce
    }

    fn mut_server_nonce_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.server_nonce
    }
}

impl ::protobuf::Message for CryptSetup {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.key)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.client_nonce)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.server_nonce)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.key.as_ref() {
            my_size += ::protobuf::rt::bytes_size(1, &v);
        }
        if let Some(ref v) = self.client_nonce.as_ref() {
            my_size += ::protobuf::rt::bytes_size(2, &v);
        }
        if let Some(ref v) = self.server_nonce.as_ref() {
            my_size += ::protobuf::rt::bytes_size(3, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.key.as_ref() {
            os.write_bytes(1, &v)?;
        }
        if let Some(ref v) = self.client_nonce.as_ref() {
            os.write_bytes(2, &v)?;
        }
        if let Some(ref v) = self.server_nonce.as_ref() {
            os.write_bytes(3, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CryptSetup {
    fn new() -> CryptSetup {
        CryptSetup::new()
    }

    fn descriptor_static(_: ::std::option::Option<CryptSetup>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "key",
                    CryptSetup::get_key_for_reflect,
                    CryptSetup::mut_key_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "client_nonce",
                    CryptSetup::get_client_nonce_for_reflect,
                    CryptSetup::mut_client_nonce_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "server_nonce",
                    CryptSetup::get_server_nonce_for_reflect,
                    CryptSetup::mut_server_nonce_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CryptSetup>(
                    "CryptSetup",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CryptSetup {
    fn clear(&mut self) {
        self.clear_key();
        self.clear_client_nonce();
        self.clear_server_nonce();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for CryptSetup {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for CryptSetup {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ContextActionModify {
    // message fields
    action: ::protobuf::SingularField<::std::string::String>,
    text: ::protobuf::SingularField<::std::string::String>,
    context: ::std::option::Option<u32>,
    operation: ::std::option::Option<ContextActionModify_Operation>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ContextActionModify {}

impl ContextActionModify {
    pub fn new() -> ContextActionModify {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ContextActionModify {
        static mut instance: ::protobuf::lazy::Lazy<ContextActionModify> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ContextActionModify,
        };
        unsafe {
            instance.get(ContextActionModify::new)
        }
    }

    // required string action = 1;

    pub fn clear_action(&mut self) {
        self.action.clear();
    }

    pub fn has_action(&self) -> bool {
        self.action.is_some()
    }

    // Param is passed by value, moved
    pub fn set_action(&mut self, v: ::std::string::String) {
        self.action = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_action(&mut self) -> &mut ::std::string::String {
        if self.action.is_none() {
            self.action.set_default();
        }
        self.action.as_mut().unwrap()
    }

    // Take field
    pub fn take_action(&mut self) -> ::std::string::String {
        self.action.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_action(&self) -> &str {
        match self.action.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_action_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.action
    }

    fn mut_action_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.action
    }

    // optional string text = 2;

    pub fn clear_text(&mut self) {
        self.text.clear();
    }

    pub fn has_text(&self) -> bool {
        self.text.is_some()
    }

    // Param is passed by value, moved
    pub fn set_text(&mut self, v: ::std::string::String) {
        self.text = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_text(&mut self) -> &mut ::std::string::String {
        if self.text.is_none() {
            self.text.set_default();
        }
        self.text.as_mut().unwrap()
    }

    // Take field
    pub fn take_text(&mut self) -> ::std::string::String {
        self.text.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_text(&self) -> &str {
        match self.text.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_text_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.text
    }

    fn mut_text_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.text
    }

    // optional uint32 context = 3;

    pub fn clear_context(&mut self) {
        self.context = ::std::option::Option::None;
    }

    pub fn has_context(&self) -> bool {
        self.context.is_some()
    }

    // Param is passed by value, moved
    pub fn set_context(&mut self, v: u32) {
        self.context = ::std::option::Option::Some(v);
    }

    pub fn get_context(&self) -> u32 {
        self.context.unwrap_or(0)
    }

    fn get_context_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.context
    }

    fn mut_context_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.context
    }

    // optional .MumbleProto.ContextActionModify.Operation operation = 4;

    pub fn clear_operation(&mut self) {
        self.operation = ::std::option::Option::None;
    }

    pub fn has_operation(&self) -> bool {
        self.operation.is_some()
    }

    // Param is passed by value, moved
    pub fn set_operation(&mut self, v: ContextActionModify_Operation) {
        self.operation = ::std::option::Option::Some(v);
    }

    pub fn get_operation(&self) -> ContextActionModify_Operation {
        self.operation.unwrap_or(ContextActionModify_Operation::Add)
    }

    fn get_operation_for_reflect(&self) -> &::std::option::Option<ContextActionModify_Operation> {
        &self.operation
    }

    fn mut_operation_for_reflect(&mut self) -> &mut ::std::option::Option<ContextActionModify_Operation> {
        &mut self.operation
    }
}

impl ::protobuf::Message for ContextActionModify {
    fn is_initialized(&self) -> bool {
        if self.action.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.action)?;
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.text)?;
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.context = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_enum()?;
                    self.operation = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(ref v) = self.action.as_ref() {
            my_size += ::protobuf::rt::string_size(1, &v);
        }
        if let Some(ref v) = self.text.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        if let Some(v) = self.context {
            my_size += ::protobuf::rt::value_size(3, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.operation {
            my_size += ::protobuf::rt::enum_size(4, v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(ref v) = self.action.as_ref() {
            os.write_string(1, &v)?;
        }
        if let Some(ref v) = self.text.as_ref() {
            os.write_string(2, &v)?;
        }
        if let Some(v) = self.context {
            os.write_uint32(3, v)?;
        }
        if let Some(v) = self.operation {
            os.write_enum(4, v.value())?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ContextActionModify {
    fn new() -> ContextActionModify {
        ContextActionModify::new()
    }

    fn descriptor_static(_: ::std::option::Option<ContextActionModify>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "action",
                    ContextActionModify::get_action_for_reflect,
                    ContextActionModify::mut_action_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "text",
                    ContextActionModify::get_text_for_reflect,
                    ContextActionModify::mut_text_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "context",
                    ContextActionModify::get_context_for_reflect,
                    ContextActionModify::mut_context_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeEnum<ContextActionModify_Operation>>(
                    "operation",
                    ContextActionModify::get_operation_for_reflect,
                    ContextActionModify::mut_operation_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ContextActionModify>(
                    "ContextActionModify",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ContextActionModify {
    fn clear(&mut self) {
        self.clear_action();
        self.clear_text();
        self.clear_context();
        self.clear_operation();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ContextActionModify {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ContextActionModify {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum ContextActionModify_Context {
    Server = 1,
    Channel = 2,
    User = 4,
}

impl ::protobuf::ProtobufEnum for ContextActionModify_Context {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<ContextActionModify_Context> {
        match value {
            1 => ::std::option::Option::Some(ContextActionModify_Context::Server),
            2 => ::std::option::Option::Some(ContextActionModify_Context::Channel),
            4 => ::std::option::Option::Some(ContextActionModify_Context::User),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [ContextActionModify_Context] = &[
            ContextActionModify_Context::Server,
            ContextActionModify_Context::Channel,
            ContextActionModify_Context::User,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<ContextActionModify_Context>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("ContextActionModify_Context", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for ContextActionModify_Context {
}

impl ::protobuf::reflect::ProtobufValue for ContextActionModify_Context {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(Clone,PartialEq,Eq,Debug,Hash)]
pub enum ContextActionModify_Operation {
    Add = 0,
    Remove = 1,
}

impl ::protobuf::ProtobufEnum for ContextActionModify_Operation {
    fn value(&self) -> i32 {
        *self as i32
    }

    fn from_i32(value: i32) -> ::std::option::Option<ContextActionModify_Operation> {
        match value {
            0 => ::std::option::Option::Some(ContextActionModify_Operation::Add),
            1 => ::std::option::Option::Some(ContextActionModify_Operation::Remove),
            _ => ::std::option::Option::None
        }
    }

    fn values() -> &'static [Self] {
        static values: &'static [ContextActionModify_Operation] = &[
            ContextActionModify_Operation::Add,
            ContextActionModify_Operation::Remove,
        ];
        values
    }

    fn enum_descriptor_static(_: ::std::option::Option<ContextActionModify_Operation>) -> &'static ::protobuf::reflect::EnumDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::EnumDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::EnumDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                ::protobuf::reflect::EnumDescriptor::new("ContextActionModify_Operation", file_descriptor_proto())
            })
        }
    }
}

impl ::std::marker::Copy for ContextActionModify_Operation {
}

impl ::protobuf::reflect::ProtobufValue for ContextActionModify_Operation {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Enum(self.descriptor())
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ContextAction {
    // message fields
    session: ::std::option::Option<u32>,
    channel_id: ::std::option::Option<u32>,
    action: ::protobuf::SingularField<::std::string::String>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ContextAction {}

impl ContextAction {
    pub fn new() -> ContextAction {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ContextAction {
        static mut instance: ::protobuf::lazy::Lazy<ContextAction> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ContextAction,
        };
        unsafe {
            instance.get(ContextAction::new)
        }
    }

    // optional uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional uint32 channel_id = 2;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // required string action = 3;

    pub fn clear_action(&mut self) {
        self.action.clear();
    }

    pub fn has_action(&self) -> bool {
        self.action.is_some()
    }

    // Param is passed by value, moved
    pub fn set_action(&mut self, v: ::std::string::String) {
        self.action = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_action(&mut self) -> &mut ::std::string::String {
        if self.action.is_none() {
            self.action.set_default();
        }
        self.action.as_mut().unwrap()
    }

    // Take field
    pub fn take_action(&mut self) -> ::std::string::String {
        self.action.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_action(&self) -> &str {
        match self.action.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_action_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.action
    }

    fn mut_action_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.action
    }
}

impl ::protobuf::Message for ContextAction {
    fn is_initialized(&self) -> bool {
        if self.action.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.action)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.action.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.session {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.channel_id {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.action.as_ref() {
            os.write_string(3, &v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ContextAction {
    fn new() -> ContextAction {
        ContextAction::new()
    }

    fn descriptor_static(_: ::std::option::Option<ContextAction>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    ContextAction::get_session_for_reflect,
                    ContextAction::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    ContextAction::get_channel_id_for_reflect,
                    ContextAction::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "action",
                    ContextAction::get_action_for_reflect,
                    ContextAction::mut_action_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ContextAction>(
                    "ContextAction",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ContextAction {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_channel_id();
        self.clear_action();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ContextAction {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ContextAction {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserList {
    // message fields
    users: ::protobuf::RepeatedField<UserList_User>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserList {}

impl UserList {
    pub fn new() -> UserList {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserList {
        static mut instance: ::protobuf::lazy::Lazy<UserList> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserList,
        };
        unsafe {
            instance.get(UserList::new)
        }
    }

    // repeated .MumbleProto.UserList.User users = 1;

    pub fn clear_users(&mut self) {
        self.users.clear();
    }

    // Param is passed by value, moved
    pub fn set_users(&mut self, v: ::protobuf::RepeatedField<UserList_User>) {
        self.users = v;
    }

    // Mutable pointer to the field.
    pub fn mut_users(&mut self) -> &mut ::protobuf::RepeatedField<UserList_User> {
        &mut self.users
    }

    // Take field
    pub fn take_users(&mut self) -> ::protobuf::RepeatedField<UserList_User> {
        ::std::mem::replace(&mut self.users, ::protobuf::RepeatedField::new())
    }

    pub fn get_users(&self) -> &[UserList_User] {
        &self.users
    }

    fn get_users_for_reflect(&self) -> &::protobuf::RepeatedField<UserList_User> {
        &self.users
    }

    fn mut_users_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<UserList_User> {
        &mut self.users
    }
}

impl ::protobuf::Message for UserList {
    fn is_initialized(&self) -> bool {
        for v in &self.users {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.users)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.users {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.users {
            os.write_tag(1, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserList {
    fn new() -> UserList {
        UserList::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserList>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<UserList_User>>(
                    "users",
                    UserList::get_users_for_reflect,
                    UserList::mut_users_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserList>(
                    "UserList",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserList {
    fn clear(&mut self) {
        self.clear_users();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserList {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserList {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserList_User {
    // message fields
    user_id: ::std::option::Option<u32>,
    name: ::protobuf::SingularField<::std::string::String>,
    last_seen: ::protobuf::SingularField<::std::string::String>,
    last_channel: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserList_User {}

impl UserList_User {
    pub fn new() -> UserList_User {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserList_User {
        static mut instance: ::protobuf::lazy::Lazy<UserList_User> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserList_User,
        };
        unsafe {
            instance.get(UserList_User::new)
        }
    }

    // required uint32 user_id = 1;

    pub fn clear_user_id(&mut self) {
        self.user_id = ::std::option::Option::None;
    }

    pub fn has_user_id(&self) -> bool {
        self.user_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_user_id(&mut self, v: u32) {
        self.user_id = ::std::option::Option::Some(v);
    }

    pub fn get_user_id(&self) -> u32 {
        self.user_id.unwrap_or(0)
    }

    fn get_user_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.user_id
    }

    fn mut_user_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.user_id
    }

    // optional string name = 2;

    pub fn clear_name(&mut self) {
        self.name.clear();
    }

    pub fn has_name(&self) -> bool {
        self.name.is_some()
    }

    // Param is passed by value, moved
    pub fn set_name(&mut self, v: ::std::string::String) {
        self.name = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_name(&mut self) -> &mut ::std::string::String {
        if self.name.is_none() {
            self.name.set_default();
        }
        self.name.as_mut().unwrap()
    }

    // Take field
    pub fn take_name(&mut self) -> ::std::string::String {
        self.name.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_name(&self) -> &str {
        match self.name.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_name_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.name
    }

    fn mut_name_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.name
    }

    // optional string last_seen = 3;

    pub fn clear_last_seen(&mut self) {
        self.last_seen.clear();
    }

    pub fn has_last_seen(&self) -> bool {
        self.last_seen.is_some()
    }

    // Param is passed by value, moved
    pub fn set_last_seen(&mut self, v: ::std::string::String) {
        self.last_seen = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_last_seen(&mut self) -> &mut ::std::string::String {
        if self.last_seen.is_none() {
            self.last_seen.set_default();
        }
        self.last_seen.as_mut().unwrap()
    }

    // Take field
    pub fn take_last_seen(&mut self) -> ::std::string::String {
        self.last_seen.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_last_seen(&self) -> &str {
        match self.last_seen.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_last_seen_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.last_seen
    }

    fn mut_last_seen_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.last_seen
    }

    // optional uint32 last_channel = 4;

    pub fn clear_last_channel(&mut self) {
        self.last_channel = ::std::option::Option::None;
    }

    pub fn has_last_channel(&self) -> bool {
        self.last_channel.is_some()
    }

    // Param is passed by value, moved
    pub fn set_last_channel(&mut self, v: u32) {
        self.last_channel = ::std::option::Option::Some(v);
    }

    pub fn get_last_channel(&self) -> u32 {
        self.last_channel.unwrap_or(0)
    }

    fn get_last_channel_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.last_channel
    }

    fn mut_last_channel_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.last_channel
    }
}

impl ::protobuf::Message for UserList_User {
    fn is_initialized(&self) -> bool {
        if self.user_id.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.user_id = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.name)?;
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.last_seen)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.last_channel = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.user_id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.name.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        if let Some(ref v) = self.last_seen.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.last_channel {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.user_id {
            os.write_uint32(1, v)?;
        }
        if let Some(ref v) = self.name.as_ref() {
            os.write_string(2, &v)?;
        }
        if let Some(ref v) = self.last_seen.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(v) = self.last_channel {
            os.write_uint32(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserList_User {
    fn new() -> UserList_User {
        UserList_User::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserList_User>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "user_id",
                    UserList_User::get_user_id_for_reflect,
                    UserList_User::mut_user_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "name",
                    UserList_User::get_name_for_reflect,
                    UserList_User::mut_name_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "last_seen",
                    UserList_User::get_last_seen_for_reflect,
                    UserList_User::mut_last_seen_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "last_channel",
                    UserList_User::get_last_channel_for_reflect,
                    UserList_User::mut_last_channel_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserList_User>(
                    "UserList_User",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserList_User {
    fn clear(&mut self) {
        self.clear_user_id();
        self.clear_name();
        self.clear_last_seen();
        self.clear_last_channel();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserList_User {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserList_User {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct VoiceTarget {
    // message fields
    id: ::std::option::Option<u32>,
    targets: ::protobuf::RepeatedField<VoiceTarget_Target>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for VoiceTarget {}

impl VoiceTarget {
    pub fn new() -> VoiceTarget {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static VoiceTarget {
        static mut instance: ::protobuf::lazy::Lazy<VoiceTarget> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const VoiceTarget,
        };
        unsafe {
            instance.get(VoiceTarget::new)
        }
    }

    // optional uint32 id = 1;

    pub fn clear_id(&mut self) {
        self.id = ::std::option::Option::None;
    }

    pub fn has_id(&self) -> bool {
        self.id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_id(&mut self, v: u32) {
        self.id = ::std::option::Option::Some(v);
    }

    pub fn get_id(&self) -> u32 {
        self.id.unwrap_or(0)
    }

    fn get_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.id
    }

    fn mut_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.id
    }

    // repeated .MumbleProto.VoiceTarget.Target targets = 2;

    pub fn clear_targets(&mut self) {
        self.targets.clear();
    }

    // Param is passed by value, moved
    pub fn set_targets(&mut self, v: ::protobuf::RepeatedField<VoiceTarget_Target>) {
        self.targets = v;
    }

    // Mutable pointer to the field.
    pub fn mut_targets(&mut self) -> &mut ::protobuf::RepeatedField<VoiceTarget_Target> {
        &mut self.targets
    }

    // Take field
    pub fn take_targets(&mut self) -> ::protobuf::RepeatedField<VoiceTarget_Target> {
        ::std::mem::replace(&mut self.targets, ::protobuf::RepeatedField::new())
    }

    pub fn get_targets(&self) -> &[VoiceTarget_Target] {
        &self.targets
    }

    fn get_targets_for_reflect(&self) -> &::protobuf::RepeatedField<VoiceTarget_Target> {
        &self.targets
    }

    fn mut_targets_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<VoiceTarget_Target> {
        &mut self.targets
    }
}

impl ::protobuf::Message for VoiceTarget {
    fn is_initialized(&self) -> bool {
        for v in &self.targets {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.id = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_repeated_message_into(wire_type, is, &mut self.targets)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        for value in &self.targets {
            let len = value.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.id {
            os.write_uint32(1, v)?;
        }
        for v in &self.targets {
            os.write_tag(2, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for VoiceTarget {
    fn new() -> VoiceTarget {
        VoiceTarget::new()
    }

    fn descriptor_static(_: ::std::option::Option<VoiceTarget>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "id",
                    VoiceTarget::get_id_for_reflect,
                    VoiceTarget::mut_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<VoiceTarget_Target>>(
                    "targets",
                    VoiceTarget::get_targets_for_reflect,
                    VoiceTarget::mut_targets_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<VoiceTarget>(
                    "VoiceTarget",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for VoiceTarget {
    fn clear(&mut self) {
        self.clear_id();
        self.clear_targets();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for VoiceTarget {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VoiceTarget {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct VoiceTarget_Target {
    // message fields
    session: ::std::vec::Vec<u32>,
    channel_id: ::std::option::Option<u32>,
    group: ::protobuf::SingularField<::std::string::String>,
    links: ::std::option::Option<bool>,
    children: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for VoiceTarget_Target {}

impl VoiceTarget_Target {
    pub fn new() -> VoiceTarget_Target {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static VoiceTarget_Target {
        static mut instance: ::protobuf::lazy::Lazy<VoiceTarget_Target> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const VoiceTarget_Target,
        };
        unsafe {
            instance.get(VoiceTarget_Target::new)
        }
    }

    // repeated uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session.clear();
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: ::std::vec::Vec<u32>) {
        self.session = v;
    }

    // Mutable pointer to the field.
    pub fn mut_session(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session
    }

    // Take field
    pub fn take_session(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.session, ::std::vec::Vec::new())
    }

    pub fn get_session(&self) -> &[u32] {
        &self.session
    }

    fn get_session_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session
    }

    // optional uint32 channel_id = 2;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional string group = 3;

    pub fn clear_group(&mut self) {
        self.group.clear();
    }

    pub fn has_group(&self) -> bool {
        self.group.is_some()
    }

    // Param is passed by value, moved
    pub fn set_group(&mut self, v: ::std::string::String) {
        self.group = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_group(&mut self) -> &mut ::std::string::String {
        if self.group.is_none() {
            self.group.set_default();
        }
        self.group.as_mut().unwrap()
    }

    // Take field
    pub fn take_group(&mut self) -> ::std::string::String {
        self.group.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_group(&self) -> &str {
        match self.group.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_group_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.group
    }

    fn mut_group_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.group
    }

    // optional bool links = 4;

    pub fn clear_links(&mut self) {
        self.links = ::std::option::Option::None;
    }

    pub fn has_links(&self) -> bool {
        self.links.is_some()
    }

    // Param is passed by value, moved
    pub fn set_links(&mut self, v: bool) {
        self.links = ::std::option::Option::Some(v);
    }

    pub fn get_links(&self) -> bool {
        self.links.unwrap_or(false)
    }

    fn get_links_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.links
    }

    fn mut_links_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.links
    }

    // optional bool children = 5;

    pub fn clear_children(&mut self) {
        self.children = ::std::option::Option::None;
    }

    pub fn has_children(&self) -> bool {
        self.children.is_some()
    }

    // Param is passed by value, moved
    pub fn set_children(&mut self, v: bool) {
        self.children = ::std::option::Option::Some(v);
    }

    pub fn get_children(&self) -> bool {
        self.children.unwrap_or(false)
    }

    fn get_children_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.children
    }

    fn mut_children_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.children
    }
}

impl ::protobuf::Message for VoiceTarget_Target {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.session)?;
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.group)?;
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.links = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.children = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.session {
            my_size += ::protobuf::rt::value_size(1, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.group.as_ref() {
            my_size += ::protobuf::rt::string_size(3, &v);
        }
        if let Some(v) = self.links {
            my_size += 2;
        }
        if let Some(v) = self.children {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.session {
            os.write_uint32(1, *v)?;
        };
        if let Some(v) = self.channel_id {
            os.write_uint32(2, v)?;
        }
        if let Some(ref v) = self.group.as_ref() {
            os.write_string(3, &v)?;
        }
        if let Some(v) = self.links {
            os.write_bool(4, v)?;
        }
        if let Some(v) = self.children {
            os.write_bool(5, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for VoiceTarget_Target {
    fn new() -> VoiceTarget_Target {
        VoiceTarget_Target::new()
    }

    fn descriptor_static(_: ::std::option::Option<VoiceTarget_Target>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    VoiceTarget_Target::get_session_for_reflect,
                    VoiceTarget_Target::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    VoiceTarget_Target::get_channel_id_for_reflect,
                    VoiceTarget_Target::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "group",
                    VoiceTarget_Target::get_group_for_reflect,
                    VoiceTarget_Target::mut_group_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "links",
                    VoiceTarget_Target::get_links_for_reflect,
                    VoiceTarget_Target::mut_links_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "children",
                    VoiceTarget_Target::get_children_for_reflect,
                    VoiceTarget_Target::mut_children_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<VoiceTarget_Target>(
                    "VoiceTarget_Target",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for VoiceTarget_Target {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_channel_id();
        self.clear_group();
        self.clear_links();
        self.clear_children();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for VoiceTarget_Target {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for VoiceTarget_Target {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct PermissionQuery {
    // message fields
    channel_id: ::std::option::Option<u32>,
    permissions: ::std::option::Option<u32>,
    flush: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for PermissionQuery {}

impl PermissionQuery {
    pub fn new() -> PermissionQuery {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static PermissionQuery {
        static mut instance: ::protobuf::lazy::Lazy<PermissionQuery> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const PermissionQuery,
        };
        unsafe {
            instance.get(PermissionQuery::new)
        }
    }

    // optional uint32 channel_id = 1;

    pub fn clear_channel_id(&mut self) {
        self.channel_id = ::std::option::Option::None;
    }

    pub fn has_channel_id(&self) -> bool {
        self.channel_id.is_some()
    }

    // Param is passed by value, moved
    pub fn set_channel_id(&mut self, v: u32) {
        self.channel_id = ::std::option::Option::Some(v);
    }

    pub fn get_channel_id(&self) -> u32 {
        self.channel_id.unwrap_or(0)
    }

    fn get_channel_id_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.channel_id
    }

    fn mut_channel_id_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.channel_id
    }

    // optional uint32 permissions = 2;

    pub fn clear_permissions(&mut self) {
        self.permissions = ::std::option::Option::None;
    }

    pub fn has_permissions(&self) -> bool {
        self.permissions.is_some()
    }

    // Param is passed by value, moved
    pub fn set_permissions(&mut self, v: u32) {
        self.permissions = ::std::option::Option::Some(v);
    }

    pub fn get_permissions(&self) -> u32 {
        self.permissions.unwrap_or(0)
    }

    fn get_permissions_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.permissions
    }

    fn mut_permissions_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.permissions
    }

    // optional bool flush = 3;

    pub fn clear_flush(&mut self) {
        self.flush = ::std::option::Option::None;
    }

    pub fn has_flush(&self) -> bool {
        self.flush.is_some()
    }

    // Param is passed by value, moved
    pub fn set_flush(&mut self, v: bool) {
        self.flush = ::std::option::Option::Some(v);
    }

    pub fn get_flush(&self) -> bool {
        self.flush.unwrap_or(false)
    }

    fn get_flush_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.flush
    }

    fn mut_flush_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.flush
    }
}

impl ::protobuf::Message for PermissionQuery {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.channel_id = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.permissions = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.flush = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.channel_id {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.permissions {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.flush {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.channel_id {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.permissions {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.flush {
            os.write_bool(3, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for PermissionQuery {
    fn new() -> PermissionQuery {
        PermissionQuery::new()
    }

    fn descriptor_static(_: ::std::option::Option<PermissionQuery>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_id",
                    PermissionQuery::get_channel_id_for_reflect,
                    PermissionQuery::mut_channel_id_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "permissions",
                    PermissionQuery::get_permissions_for_reflect,
                    PermissionQuery::mut_permissions_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "flush",
                    PermissionQuery::get_flush_for_reflect,
                    PermissionQuery::mut_flush_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<PermissionQuery>(
                    "PermissionQuery",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for PermissionQuery {
    fn clear(&mut self) {
        self.clear_channel_id();
        self.clear_permissions();
        self.clear_flush();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for PermissionQuery {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for PermissionQuery {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct CodecVersion {
    // message fields
    alpha: ::std::option::Option<i32>,
    beta: ::std::option::Option<i32>,
    prefer_alpha: ::std::option::Option<bool>,
    opus: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for CodecVersion {}

impl CodecVersion {
    pub fn new() -> CodecVersion {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static CodecVersion {
        static mut instance: ::protobuf::lazy::Lazy<CodecVersion> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const CodecVersion,
        };
        unsafe {
            instance.get(CodecVersion::new)
        }
    }

    // required int32 alpha = 1;

    pub fn clear_alpha(&mut self) {
        self.alpha = ::std::option::Option::None;
    }

    pub fn has_alpha(&self) -> bool {
        self.alpha.is_some()
    }

    // Param is passed by value, moved
    pub fn set_alpha(&mut self, v: i32) {
        self.alpha = ::std::option::Option::Some(v);
    }

    pub fn get_alpha(&self) -> i32 {
        self.alpha.unwrap_or(0)
    }

    fn get_alpha_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.alpha
    }

    fn mut_alpha_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.alpha
    }

    // required int32 beta = 2;

    pub fn clear_beta(&mut self) {
        self.beta = ::std::option::Option::None;
    }

    pub fn has_beta(&self) -> bool {
        self.beta.is_some()
    }

    // Param is passed by value, moved
    pub fn set_beta(&mut self, v: i32) {
        self.beta = ::std::option::Option::Some(v);
    }

    pub fn get_beta(&self) -> i32 {
        self.beta.unwrap_or(0)
    }

    fn get_beta_for_reflect(&self) -> &::std::option::Option<i32> {
        &self.beta
    }

    fn mut_beta_for_reflect(&mut self) -> &mut ::std::option::Option<i32> {
        &mut self.beta
    }

    // required bool prefer_alpha = 3;

    pub fn clear_prefer_alpha(&mut self) {
        self.prefer_alpha = ::std::option::Option::None;
    }

    pub fn has_prefer_alpha(&self) -> bool {
        self.prefer_alpha.is_some()
    }

    // Param is passed by value, moved
    pub fn set_prefer_alpha(&mut self, v: bool) {
        self.prefer_alpha = ::std::option::Option::Some(v);
    }

    pub fn get_prefer_alpha(&self) -> bool {
        self.prefer_alpha.unwrap_or(true)
    }

    fn get_prefer_alpha_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.prefer_alpha
    }

    fn mut_prefer_alpha_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.prefer_alpha
    }

    // optional bool opus = 4;

    pub fn clear_opus(&mut self) {
        self.opus = ::std::option::Option::None;
    }

    pub fn has_opus(&self) -> bool {
        self.opus.is_some()
    }

    // Param is passed by value, moved
    pub fn set_opus(&mut self, v: bool) {
        self.opus = ::std::option::Option::Some(v);
    }

    pub fn get_opus(&self) -> bool {
        self.opus.unwrap_or(false)
    }

    fn get_opus_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.opus
    }

    fn mut_opus_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.opus
    }
}

impl ::protobuf::Message for CodecVersion {
    fn is_initialized(&self) -> bool {
        if self.alpha.is_none() {
            return false;
        }
        if self.beta.is_none() {
            return false;
        }
        if self.prefer_alpha.is_none() {
            return false;
        }
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.alpha = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_int32()?;
                    self.beta = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.prefer_alpha = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.opus = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.alpha {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.beta {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.prefer_alpha {
            my_size += 2;
        }
        if let Some(v) = self.opus {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.alpha {
            os.write_int32(1, v)?;
        }
        if let Some(v) = self.beta {
            os.write_int32(2, v)?;
        }
        if let Some(v) = self.prefer_alpha {
            os.write_bool(3, v)?;
        }
        if let Some(v) = self.opus {
            os.write_bool(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for CodecVersion {
    fn new() -> CodecVersion {
        CodecVersion::new()
    }

    fn descriptor_static(_: ::std::option::Option<CodecVersion>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "alpha",
                    CodecVersion::get_alpha_for_reflect,
                    CodecVersion::mut_alpha_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "beta",
                    CodecVersion::get_beta_for_reflect,
                    CodecVersion::mut_beta_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "prefer_alpha",
                    CodecVersion::get_prefer_alpha_for_reflect,
                    CodecVersion::mut_prefer_alpha_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "opus",
                    CodecVersion::get_opus_for_reflect,
                    CodecVersion::mut_opus_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<CodecVersion>(
                    "CodecVersion",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for CodecVersion {
    fn clear(&mut self) {
        self.clear_alpha();
        self.clear_beta();
        self.clear_prefer_alpha();
        self.clear_opus();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for CodecVersion {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for CodecVersion {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserStats {
    // message fields
    session: ::std::option::Option<u32>,
    stats_only: ::std::option::Option<bool>,
    certificates: ::protobuf::RepeatedField<::std::vec::Vec<u8>>,
    from_client: ::protobuf::SingularPtrField<UserStats_Stats>,
    from_server: ::protobuf::SingularPtrField<UserStats_Stats>,
    udp_packets: ::std::option::Option<u32>,
    tcp_packets: ::std::option::Option<u32>,
    udp_ping_avg: ::std::option::Option<f32>,
    udp_ping_var: ::std::option::Option<f32>,
    tcp_ping_avg: ::std::option::Option<f32>,
    tcp_ping_var: ::std::option::Option<f32>,
    version: ::protobuf::SingularPtrField<Version>,
    celt_versions: ::std::vec::Vec<i32>,
    address: ::protobuf::SingularField<::std::vec::Vec<u8>>,
    bandwidth: ::std::option::Option<u32>,
    onlinesecs: ::std::option::Option<u32>,
    idlesecs: ::std::option::Option<u32>,
    strong_certificate: ::std::option::Option<bool>,
    opus: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserStats {}

impl UserStats {
    pub fn new() -> UserStats {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserStats {
        static mut instance: ::protobuf::lazy::Lazy<UserStats> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserStats,
        };
        unsafe {
            instance.get(UserStats::new)
        }
    }

    // optional uint32 session = 1;

    pub fn clear_session(&mut self) {
        self.session = ::std::option::Option::None;
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }

    // Param is passed by value, moved
    pub fn set_session(&mut self, v: u32) {
        self.session = ::std::option::Option::Some(v);
    }

    pub fn get_session(&self) -> u32 {
        self.session.unwrap_or(0)
    }

    fn get_session_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.session
    }

    fn mut_session_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.session
    }

    // optional bool stats_only = 2;

    pub fn clear_stats_only(&mut self) {
        self.stats_only = ::std::option::Option::None;
    }

    pub fn has_stats_only(&self) -> bool {
        self.stats_only.is_some()
    }

    // Param is passed by value, moved
    pub fn set_stats_only(&mut self, v: bool) {
        self.stats_only = ::std::option::Option::Some(v);
    }

    pub fn get_stats_only(&self) -> bool {
        self.stats_only.unwrap_or(false)
    }

    fn get_stats_only_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.stats_only
    }

    fn mut_stats_only_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.stats_only
    }

    // repeated bytes certificates = 3;

    pub fn clear_certificates(&mut self) {
        self.certificates.clear();
    }

    // Param is passed by value, moved
    pub fn set_certificates(&mut self, v: ::protobuf::RepeatedField<::std::vec::Vec<u8>>) {
        self.certificates = v;
    }

    // Mutable pointer to the field.
    pub fn mut_certificates(&mut self) -> &mut ::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        &mut self.certificates
    }

    // Take field
    pub fn take_certificates(&mut self) -> ::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        ::std::mem::replace(&mut self.certificates, ::protobuf::RepeatedField::new())
    }

    pub fn get_certificates(&self) -> &[::std::vec::Vec<u8>] {
        &self.certificates
    }

    fn get_certificates_for_reflect(&self) -> &::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        &self.certificates
    }

    fn mut_certificates_for_reflect(&mut self) -> &mut ::protobuf::RepeatedField<::std::vec::Vec<u8>> {
        &mut self.certificates
    }

    // optional .MumbleProto.UserStats.Stats from_client = 4;

    pub fn clear_from_client(&mut self) {
        self.from_client.clear();
    }

    pub fn has_from_client(&self) -> bool {
        self.from_client.is_some()
    }

    // Param is passed by value, moved
    pub fn set_from_client(&mut self, v: UserStats_Stats) {
        self.from_client = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_from_client(&mut self) -> &mut UserStats_Stats {
        if self.from_client.is_none() {
            self.from_client.set_default();
        }
        self.from_client.as_mut().unwrap()
    }

    // Take field
    pub fn take_from_client(&mut self) -> UserStats_Stats {
        self.from_client.take().unwrap_or_else(|| UserStats_Stats::new())
    }

    pub fn get_from_client(&self) -> &UserStats_Stats {
        self.from_client.as_ref().unwrap_or_else(|| UserStats_Stats::default_instance())
    }

    fn get_from_client_for_reflect(&self) -> &::protobuf::SingularPtrField<UserStats_Stats> {
        &self.from_client
    }

    fn mut_from_client_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<UserStats_Stats> {
        &mut self.from_client
    }

    // optional .MumbleProto.UserStats.Stats from_server = 5;

    pub fn clear_from_server(&mut self) {
        self.from_server.clear();
    }

    pub fn has_from_server(&self) -> bool {
        self.from_server.is_some()
    }

    // Param is passed by value, moved
    pub fn set_from_server(&mut self, v: UserStats_Stats) {
        self.from_server = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_from_server(&mut self) -> &mut UserStats_Stats {
        if self.from_server.is_none() {
            self.from_server.set_default();
        }
        self.from_server.as_mut().unwrap()
    }

    // Take field
    pub fn take_from_server(&mut self) -> UserStats_Stats {
        self.from_server.take().unwrap_or_else(|| UserStats_Stats::new())
    }

    pub fn get_from_server(&self) -> &UserStats_Stats {
        self.from_server.as_ref().unwrap_or_else(|| UserStats_Stats::default_instance())
    }

    fn get_from_server_for_reflect(&self) -> &::protobuf::SingularPtrField<UserStats_Stats> {
        &self.from_server
    }

    fn mut_from_server_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<UserStats_Stats> {
        &mut self.from_server
    }

    // optional uint32 udp_packets = 6;

    pub fn clear_udp_packets(&mut self) {
        self.udp_packets = ::std::option::Option::None;
    }

    pub fn has_udp_packets(&self) -> bool {
        self.udp_packets.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_packets(&mut self, v: u32) {
        self.udp_packets = ::std::option::Option::Some(v);
    }

    pub fn get_udp_packets(&self) -> u32 {
        self.udp_packets.unwrap_or(0)
    }

    fn get_udp_packets_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.udp_packets
    }

    fn mut_udp_packets_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.udp_packets
    }

    // optional uint32 tcp_packets = 7;

    pub fn clear_tcp_packets(&mut self) {
        self.tcp_packets = ::std::option::Option::None;
    }

    pub fn has_tcp_packets(&self) -> bool {
        self.tcp_packets.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_packets(&mut self, v: u32) {
        self.tcp_packets = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_packets(&self) -> u32 {
        self.tcp_packets.unwrap_or(0)
    }

    fn get_tcp_packets_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.tcp_packets
    }

    fn mut_tcp_packets_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.tcp_packets
    }

    // optional float udp_ping_avg = 8;

    pub fn clear_udp_ping_avg(&mut self) {
        self.udp_ping_avg = ::std::option::Option::None;
    }

    pub fn has_udp_ping_avg(&self) -> bool {
        self.udp_ping_avg.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_ping_avg(&mut self, v: f32) {
        self.udp_ping_avg = ::std::option::Option::Some(v);
    }

    pub fn get_udp_ping_avg(&self) -> f32 {
        self.udp_ping_avg.unwrap_or(0.)
    }

    fn get_udp_ping_avg_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.udp_ping_avg
    }

    fn mut_udp_ping_avg_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.udp_ping_avg
    }

    // optional float udp_ping_var = 9;

    pub fn clear_udp_ping_var(&mut self) {
        self.udp_ping_var = ::std::option::Option::None;
    }

    pub fn has_udp_ping_var(&self) -> bool {
        self.udp_ping_var.is_some()
    }

    // Param is passed by value, moved
    pub fn set_udp_ping_var(&mut self, v: f32) {
        self.udp_ping_var = ::std::option::Option::Some(v);
    }

    pub fn get_udp_ping_var(&self) -> f32 {
        self.udp_ping_var.unwrap_or(0.)
    }

    fn get_udp_ping_var_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.udp_ping_var
    }

    fn mut_udp_ping_var_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.udp_ping_var
    }

    // optional float tcp_ping_avg = 10;

    pub fn clear_tcp_ping_avg(&mut self) {
        self.tcp_ping_avg = ::std::option::Option::None;
    }

    pub fn has_tcp_ping_avg(&self) -> bool {
        self.tcp_ping_avg.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_ping_avg(&mut self, v: f32) {
        self.tcp_ping_avg = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_ping_avg(&self) -> f32 {
        self.tcp_ping_avg.unwrap_or(0.)
    }

    fn get_tcp_ping_avg_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.tcp_ping_avg
    }

    fn mut_tcp_ping_avg_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.tcp_ping_avg
    }

    // optional float tcp_ping_var = 11;

    pub fn clear_tcp_ping_var(&mut self) {
        self.tcp_ping_var = ::std::option::Option::None;
    }

    pub fn has_tcp_ping_var(&self) -> bool {
        self.tcp_ping_var.is_some()
    }

    // Param is passed by value, moved
    pub fn set_tcp_ping_var(&mut self, v: f32) {
        self.tcp_ping_var = ::std::option::Option::Some(v);
    }

    pub fn get_tcp_ping_var(&self) -> f32 {
        self.tcp_ping_var.unwrap_or(0.)
    }

    fn get_tcp_ping_var_for_reflect(&self) -> &::std::option::Option<f32> {
        &self.tcp_ping_var
    }

    fn mut_tcp_ping_var_for_reflect(&mut self) -> &mut ::std::option::Option<f32> {
        &mut self.tcp_ping_var
    }

    // optional .MumbleProto.Version version = 12;

    pub fn clear_version(&mut self) {
        self.version.clear();
    }

    pub fn has_version(&self) -> bool {
        self.version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_version(&mut self, v: Version) {
        self.version = ::protobuf::SingularPtrField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_version(&mut self) -> &mut Version {
        if self.version.is_none() {
            self.version.set_default();
        }
        self.version.as_mut().unwrap()
    }

    // Take field
    pub fn take_version(&mut self) -> Version {
        self.version.take().unwrap_or_else(|| Version::new())
    }

    pub fn get_version(&self) -> &Version {
        self.version.as_ref().unwrap_or_else(|| Version::default_instance())
    }

    fn get_version_for_reflect(&self) -> &::protobuf::SingularPtrField<Version> {
        &self.version
    }

    fn mut_version_for_reflect(&mut self) -> &mut ::protobuf::SingularPtrField<Version> {
        &mut self.version
    }

    // repeated int32 celt_versions = 13;

    pub fn clear_celt_versions(&mut self) {
        self.celt_versions.clear();
    }

    // Param is passed by value, moved
    pub fn set_celt_versions(&mut self, v: ::std::vec::Vec<i32>) {
        self.celt_versions = v;
    }

    // Mutable pointer to the field.
    pub fn mut_celt_versions(&mut self) -> &mut ::std::vec::Vec<i32> {
        &mut self.celt_versions
    }

    // Take field
    pub fn take_celt_versions(&mut self) -> ::std::vec::Vec<i32> {
        ::std::mem::replace(&mut self.celt_versions, ::std::vec::Vec::new())
    }

    pub fn get_celt_versions(&self) -> &[i32] {
        &self.celt_versions
    }

    fn get_celt_versions_for_reflect(&self) -> &::std::vec::Vec<i32> {
        &self.celt_versions
    }

    fn mut_celt_versions_for_reflect(&mut self) -> &mut ::std::vec::Vec<i32> {
        &mut self.celt_versions
    }

    // optional bytes address = 14;

    pub fn clear_address(&mut self) {
        self.address.clear();
    }

    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    // Param is passed by value, moved
    pub fn set_address(&mut self, v: ::std::vec::Vec<u8>) {
        self.address = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_address(&mut self) -> &mut ::std::vec::Vec<u8> {
        if self.address.is_none() {
            self.address.set_default();
        }
        self.address.as_mut().unwrap()
    }

    // Take field
    pub fn take_address(&mut self) -> ::std::vec::Vec<u8> {
        self.address.take().unwrap_or_else(|| ::std::vec::Vec::new())
    }

    pub fn get_address(&self) -> &[u8] {
        match self.address.as_ref() {
            Some(v) => &v,
            None => &[],
        }
    }

    fn get_address_for_reflect(&self) -> &::protobuf::SingularField<::std::vec::Vec<u8>> {
        &self.address
    }

    fn mut_address_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::vec::Vec<u8>> {
        &mut self.address
    }

    // optional uint32 bandwidth = 15;

    pub fn clear_bandwidth(&mut self) {
        self.bandwidth = ::std::option::Option::None;
    }

    pub fn has_bandwidth(&self) -> bool {
        self.bandwidth.is_some()
    }

    // Param is passed by value, moved
    pub fn set_bandwidth(&mut self, v: u32) {
        self.bandwidth = ::std::option::Option::Some(v);
    }

    pub fn get_bandwidth(&self) -> u32 {
        self.bandwidth.unwrap_or(0)
    }

    fn get_bandwidth_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.bandwidth
    }

    fn mut_bandwidth_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.bandwidth
    }

    // optional uint32 onlinesecs = 16;

    pub fn clear_onlinesecs(&mut self) {
        self.onlinesecs = ::std::option::Option::None;
    }

    pub fn has_onlinesecs(&self) -> bool {
        self.onlinesecs.is_some()
    }

    // Param is passed by value, moved
    pub fn set_onlinesecs(&mut self, v: u32) {
        self.onlinesecs = ::std::option::Option::Some(v);
    }

    pub fn get_onlinesecs(&self) -> u32 {
        self.onlinesecs.unwrap_or(0)
    }

    fn get_onlinesecs_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.onlinesecs
    }

    fn mut_onlinesecs_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.onlinesecs
    }

    // optional uint32 idlesecs = 17;

    pub fn clear_idlesecs(&mut self) {
        self.idlesecs = ::std::option::Option::None;
    }

    pub fn has_idlesecs(&self) -> bool {
        self.idlesecs.is_some()
    }

    // Param is passed by value, moved
    pub fn set_idlesecs(&mut self, v: u32) {
        self.idlesecs = ::std::option::Option::Some(v);
    }

    pub fn get_idlesecs(&self) -> u32 {
        self.idlesecs.unwrap_or(0)
    }

    fn get_idlesecs_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.idlesecs
    }

    fn mut_idlesecs_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.idlesecs
    }

    // optional bool strong_certificate = 18;

    pub fn clear_strong_certificate(&mut self) {
        self.strong_certificate = ::std::option::Option::None;
    }

    pub fn has_strong_certificate(&self) -> bool {
        self.strong_certificate.is_some()
    }

    // Param is passed by value, moved
    pub fn set_strong_certificate(&mut self, v: bool) {
        self.strong_certificate = ::std::option::Option::Some(v);
    }

    pub fn get_strong_certificate(&self) -> bool {
        self.strong_certificate.unwrap_or(false)
    }

    fn get_strong_certificate_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.strong_certificate
    }

    fn mut_strong_certificate_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.strong_certificate
    }

    // optional bool opus = 19;

    pub fn clear_opus(&mut self) {
        self.opus = ::std::option::Option::None;
    }

    pub fn has_opus(&self) -> bool {
        self.opus.is_some()
    }

    // Param is passed by value, moved
    pub fn set_opus(&mut self, v: bool) {
        self.opus = ::std::option::Option::Some(v);
    }

    pub fn get_opus(&self) -> bool {
        self.opus.unwrap_or(false)
    }

    fn get_opus_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.opus
    }

    fn mut_opus_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.opus
    }
}

impl ::protobuf::Message for UserStats {
    fn is_initialized(&self) -> bool {
        for v in &self.from_client {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.from_server {
            if !v.is_initialized() {
                return false;
            }
        };
        for v in &self.version {
            if !v.is_initialized() {
                return false;
            }
        };
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.session = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.stats_only = ::std::option::Option::Some(tmp);
                },
                3 => {
                    ::protobuf::rt::read_repeated_bytes_into(wire_type, is, &mut self.certificates)?;
                },
                4 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.from_client)?;
                },
                5 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.from_server)?;
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.udp_packets = ::std::option::Option::Some(tmp);
                },
                7 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.tcp_packets = ::std::option::Option::Some(tmp);
                },
                8 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.udp_ping_avg = ::std::option::Option::Some(tmp);
                },
                9 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.udp_ping_var = ::std::option::Option::Some(tmp);
                },
                10 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.tcp_ping_avg = ::std::option::Option::Some(tmp);
                },
                11 => {
                    if wire_type != ::protobuf::wire_format::WireTypeFixed32 {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_float()?;
                    self.tcp_ping_var = ::std::option::Option::Some(tmp);
                },
                12 => {
                    ::protobuf::rt::read_singular_message_into(wire_type, is, &mut self.version)?;
                },
                13 => {
                    ::protobuf::rt::read_repeated_int32_into(wire_type, is, &mut self.celt_versions)?;
                },
                14 => {
                    ::protobuf::rt::read_singular_bytes_into(wire_type, is, &mut self.address)?;
                },
                15 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.bandwidth = ::std::option::Option::Some(tmp);
                },
                16 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.onlinesecs = ::std::option::Option::Some(tmp);
                },
                17 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.idlesecs = ::std::option::Option::Some(tmp);
                },
                18 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.strong_certificate = ::std::option::Option::Some(tmp);
                },
                19 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.opus = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.session {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.stats_only {
            my_size += 2;
        }
        for value in &self.certificates {
            my_size += ::protobuf::rt::bytes_size(3, &value);
        };
        if let Some(ref v) = self.from_client.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(ref v) = self.from_server.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        if let Some(v) = self.udp_packets {
            my_size += ::protobuf::rt::value_size(6, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.tcp_packets {
            my_size += ::protobuf::rt::value_size(7, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.udp_ping_avg {
            my_size += 5;
        }
        if let Some(v) = self.udp_ping_var {
            my_size += 5;
        }
        if let Some(v) = self.tcp_ping_avg {
            my_size += 5;
        }
        if let Some(v) = self.tcp_ping_var {
            my_size += 5;
        }
        if let Some(ref v) = self.version.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint32_size(len) + len;
        }
        for value in &self.celt_versions {
            my_size += ::protobuf::rt::value_size(13, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        if let Some(ref v) = self.address.as_ref() {
            my_size += ::protobuf::rt::bytes_size(14, &v);
        }
        if let Some(v) = self.bandwidth {
            my_size += ::protobuf::rt::value_size(15, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.onlinesecs {
            my_size += ::protobuf::rt::value_size(16, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.idlesecs {
            my_size += ::protobuf::rt::value_size(17, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.strong_certificate {
            my_size += 3;
        }
        if let Some(v) = self.opus {
            my_size += 3;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.session {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.stats_only {
            os.write_bool(2, v)?;
        }
        for v in &self.certificates {
            os.write_bytes(3, &v)?;
        };
        if let Some(ref v) = self.from_client.as_ref() {
            os.write_tag(4, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(ref v) = self.from_server.as_ref() {
            os.write_tag(5, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        if let Some(v) = self.udp_packets {
            os.write_uint32(6, v)?;
        }
        if let Some(v) = self.tcp_packets {
            os.write_uint32(7, v)?;
        }
        if let Some(v) = self.udp_ping_avg {
            os.write_float(8, v)?;
        }
        if let Some(v) = self.udp_ping_var {
            os.write_float(9, v)?;
        }
        if let Some(v) = self.tcp_ping_avg {
            os.write_float(10, v)?;
        }
        if let Some(v) = self.tcp_ping_var {
            os.write_float(11, v)?;
        }
        if let Some(ref v) = self.version.as_ref() {
            os.write_tag(12, ::protobuf::wire_format::WireTypeLengthDelimited)?;
            os.write_raw_varint32(v.get_cached_size())?;
            v.write_to_with_cached_sizes(os)?;
        }
        for v in &self.celt_versions {
            os.write_int32(13, *v)?;
        };
        if let Some(ref v) = self.address.as_ref() {
            os.write_bytes(14, &v)?;
        }
        if let Some(v) = self.bandwidth {
            os.write_uint32(15, v)?;
        }
        if let Some(v) = self.onlinesecs {
            os.write_uint32(16, v)?;
        }
        if let Some(v) = self.idlesecs {
            os.write_uint32(17, v)?;
        }
        if let Some(v) = self.strong_certificate {
            os.write_bool(18, v)?;
        }
        if let Some(v) = self.opus {
            os.write_bool(19, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserStats {
    fn new() -> UserStats {
        UserStats::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserStats>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session",
                    UserStats::get_session_for_reflect,
                    UserStats::mut_session_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "stats_only",
                    UserStats::get_stats_only_for_reflect,
                    UserStats::mut_stats_only_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_repeated_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "certificates",
                    UserStats::get_certificates_for_reflect,
                    UserStats::mut_certificates_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<UserStats_Stats>>(
                    "from_client",
                    UserStats::get_from_client_for_reflect,
                    UserStats::mut_from_client_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<UserStats_Stats>>(
                    "from_server",
                    UserStats::get_from_server_for_reflect,
                    UserStats::mut_from_server_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "udp_packets",
                    UserStats::get_udp_packets_for_reflect,
                    UserStats::mut_udp_packets_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "tcp_packets",
                    UserStats::get_tcp_packets_for_reflect,
                    UserStats::mut_tcp_packets_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "udp_ping_avg",
                    UserStats::get_udp_ping_avg_for_reflect,
                    UserStats::mut_udp_ping_avg_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "udp_ping_var",
                    UserStats::get_udp_ping_var_for_reflect,
                    UserStats::mut_udp_ping_var_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "tcp_ping_avg",
                    UserStats::get_tcp_ping_avg_for_reflect,
                    UserStats::mut_tcp_ping_avg_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeFloat>(
                    "tcp_ping_var",
                    UserStats::get_tcp_ping_var_for_reflect,
                    UserStats::mut_tcp_ping_var_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_ptr_field_accessor::<_, ::protobuf::types::ProtobufTypeMessage<Version>>(
                    "version",
                    UserStats::get_version_for_reflect,
                    UserStats::mut_version_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeInt32>(
                    "celt_versions",
                    UserStats::get_celt_versions_for_reflect,
                    UserStats::mut_celt_versions_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeBytes>(
                    "address",
                    UserStats::get_address_for_reflect,
                    UserStats::mut_address_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "bandwidth",
                    UserStats::get_bandwidth_for_reflect,
                    UserStats::mut_bandwidth_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "onlinesecs",
                    UserStats::get_onlinesecs_for_reflect,
                    UserStats::mut_onlinesecs_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "idlesecs",
                    UserStats::get_idlesecs_for_reflect,
                    UserStats::mut_idlesecs_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "strong_certificate",
                    UserStats::get_strong_certificate_for_reflect,
                    UserStats::mut_strong_certificate_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "opus",
                    UserStats::get_opus_for_reflect,
                    UserStats::mut_opus_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserStats>(
                    "UserStats",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserStats {
    fn clear(&mut self) {
        self.clear_session();
        self.clear_stats_only();
        self.clear_certificates();
        self.clear_from_client();
        self.clear_from_server();
        self.clear_udp_packets();
        self.clear_tcp_packets();
        self.clear_udp_ping_avg();
        self.clear_udp_ping_var();
        self.clear_tcp_ping_avg();
        self.clear_tcp_ping_var();
        self.clear_version();
        self.clear_celt_versions();
        self.clear_address();
        self.clear_bandwidth();
        self.clear_onlinesecs();
        self.clear_idlesecs();
        self.clear_strong_certificate();
        self.clear_opus();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserStats {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserStats {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct UserStats_Stats {
    // message fields
    good: ::std::option::Option<u32>,
    late: ::std::option::Option<u32>,
    lost: ::std::option::Option<u32>,
    resync: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for UserStats_Stats {}

impl UserStats_Stats {
    pub fn new() -> UserStats_Stats {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static UserStats_Stats {
        static mut instance: ::protobuf::lazy::Lazy<UserStats_Stats> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const UserStats_Stats,
        };
        unsafe {
            instance.get(UserStats_Stats::new)
        }
    }

    // optional uint32 good = 1;

    pub fn clear_good(&mut self) {
        self.good = ::std::option::Option::None;
    }

    pub fn has_good(&self) -> bool {
        self.good.is_some()
    }

    // Param is passed by value, moved
    pub fn set_good(&mut self, v: u32) {
        self.good = ::std::option::Option::Some(v);
    }

    pub fn get_good(&self) -> u32 {
        self.good.unwrap_or(0)
    }

    fn get_good_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.good
    }

    fn mut_good_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.good
    }

    // optional uint32 late = 2;

    pub fn clear_late(&mut self) {
        self.late = ::std::option::Option::None;
    }

    pub fn has_late(&self) -> bool {
        self.late.is_some()
    }

    // Param is passed by value, moved
    pub fn set_late(&mut self, v: u32) {
        self.late = ::std::option::Option::Some(v);
    }

    pub fn get_late(&self) -> u32 {
        self.late.unwrap_or(0)
    }

    fn get_late_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.late
    }

    fn mut_late_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.late
    }

    // optional uint32 lost = 3;

    pub fn clear_lost(&mut self) {
        self.lost = ::std::option::Option::None;
    }

    pub fn has_lost(&self) -> bool {
        self.lost.is_some()
    }

    // Param is passed by value, moved
    pub fn set_lost(&mut self, v: u32) {
        self.lost = ::std::option::Option::Some(v);
    }

    pub fn get_lost(&self) -> u32 {
        self.lost.unwrap_or(0)
    }

    fn get_lost_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.lost
    }

    fn mut_lost_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.lost
    }

    // optional uint32 resync = 4;

    pub fn clear_resync(&mut self) {
        self.resync = ::std::option::Option::None;
    }

    pub fn has_resync(&self) -> bool {
        self.resync.is_some()
    }

    // Param is passed by value, moved
    pub fn set_resync(&mut self, v: u32) {
        self.resync = ::std::option::Option::Some(v);
    }

    pub fn get_resync(&self) -> u32 {
        self.resync.unwrap_or(0)
    }

    fn get_resync_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.resync
    }

    fn mut_resync_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.resync
    }
}

impl ::protobuf::Message for UserStats_Stats {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.good = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.late = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.lost = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.resync = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.good {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.late {
            my_size += ::protobuf::rt::value_size(2, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.lost {
            my_size += ::protobuf::rt::value_size(3, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.resync {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.good {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.late {
            os.write_uint32(2, v)?;
        }
        if let Some(v) = self.lost {
            os.write_uint32(3, v)?;
        }
        if let Some(v) = self.resync {
            os.write_uint32(4, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for UserStats_Stats {
    fn new() -> UserStats_Stats {
        UserStats_Stats::new()
    }

    fn descriptor_static(_: ::std::option::Option<UserStats_Stats>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "good",
                    UserStats_Stats::get_good_for_reflect,
                    UserStats_Stats::mut_good_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "late",
                    UserStats_Stats::get_late_for_reflect,
                    UserStats_Stats::mut_late_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "lost",
                    UserStats_Stats::get_lost_for_reflect,
                    UserStats_Stats::mut_lost_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "resync",
                    UserStats_Stats::get_resync_for_reflect,
                    UserStats_Stats::mut_resync_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<UserStats_Stats>(
                    "UserStats_Stats",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for UserStats_Stats {
    fn clear(&mut self) {
        self.clear_good();
        self.clear_late();
        self.clear_lost();
        self.clear_resync();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for UserStats_Stats {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for UserStats_Stats {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct RequestBlob {
    // message fields
    session_texture: ::std::vec::Vec<u32>,
    session_comment: ::std::vec::Vec<u32>,
    channel_description: ::std::vec::Vec<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for RequestBlob {}

impl RequestBlob {
    pub fn new() -> RequestBlob {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static RequestBlob {
        static mut instance: ::protobuf::lazy::Lazy<RequestBlob> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const RequestBlob,
        };
        unsafe {
            instance.get(RequestBlob::new)
        }
    }

    // repeated uint32 session_texture = 1;

    pub fn clear_session_texture(&mut self) {
        self.session_texture.clear();
    }

    // Param is passed by value, moved
    pub fn set_session_texture(&mut self, v: ::std::vec::Vec<u32>) {
        self.session_texture = v;
    }

    // Mutable pointer to the field.
    pub fn mut_session_texture(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session_texture
    }

    // Take field
    pub fn take_session_texture(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.session_texture, ::std::vec::Vec::new())
    }

    pub fn get_session_texture(&self) -> &[u32] {
        &self.session_texture
    }

    fn get_session_texture_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.session_texture
    }

    fn mut_session_texture_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session_texture
    }

    // repeated uint32 session_comment = 2;

    pub fn clear_session_comment(&mut self) {
        self.session_comment.clear();
    }

    // Param is passed by value, moved
    pub fn set_session_comment(&mut self, v: ::std::vec::Vec<u32>) {
        self.session_comment = v;
    }

    // Mutable pointer to the field.
    pub fn mut_session_comment(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session_comment
    }

    // Take field
    pub fn take_session_comment(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.session_comment, ::std::vec::Vec::new())
    }

    pub fn get_session_comment(&self) -> &[u32] {
        &self.session_comment
    }

    fn get_session_comment_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.session_comment
    }

    fn mut_session_comment_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.session_comment
    }

    // repeated uint32 channel_description = 3;

    pub fn clear_channel_description(&mut self) {
        self.channel_description.clear();
    }

    // Param is passed by value, moved
    pub fn set_channel_description(&mut self, v: ::std::vec::Vec<u32>) {
        self.channel_description = v;
    }

    // Mutable pointer to the field.
    pub fn mut_channel_description(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.channel_description
    }

    // Take field
    pub fn take_channel_description(&mut self) -> ::std::vec::Vec<u32> {
        ::std::mem::replace(&mut self.channel_description, ::std::vec::Vec::new())
    }

    pub fn get_channel_description(&self) -> &[u32] {
        &self.channel_description
    }

    fn get_channel_description_for_reflect(&self) -> &::std::vec::Vec<u32> {
        &self.channel_description
    }

    fn mut_channel_description_for_reflect(&mut self) -> &mut ::std::vec::Vec<u32> {
        &mut self.channel_description
    }
}

impl ::protobuf::Message for RequestBlob {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.session_texture)?;
                },
                2 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.session_comment)?;
                },
                3 => {
                    ::protobuf::rt::read_repeated_uint32_into(wire_type, is, &mut self.channel_description)?;
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        for value in &self.session_texture {
            my_size += ::protobuf::rt::value_size(1, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.session_comment {
            my_size += ::protobuf::rt::value_size(2, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        for value in &self.channel_description {
            my_size += ::protobuf::rt::value_size(3, *value, ::protobuf::wire_format::WireTypeVarint);
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        for v in &self.session_texture {
            os.write_uint32(1, *v)?;
        };
        for v in &self.session_comment {
            os.write_uint32(2, *v)?;
        };
        for v in &self.channel_description {
            os.write_uint32(3, *v)?;
        };
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for RequestBlob {
    fn new() -> RequestBlob {
        RequestBlob::new()
    }

    fn descriptor_static(_: ::std::option::Option<RequestBlob>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session_texture",
                    RequestBlob::get_session_texture_for_reflect,
                    RequestBlob::mut_session_texture_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "session_comment",
                    RequestBlob::get_session_comment_for_reflect,
                    RequestBlob::mut_session_comment_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_vec_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "channel_description",
                    RequestBlob::get_channel_description_for_reflect,
                    RequestBlob::mut_channel_description_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<RequestBlob>(
                    "RequestBlob",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for RequestBlob {
    fn clear(&mut self) {
        self.clear_session_texture();
        self.clear_session_comment();
        self.clear_channel_description();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for RequestBlob {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for RequestBlob {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct ServerConfig {
    // message fields
    max_bandwidth: ::std::option::Option<u32>,
    welcome_text: ::protobuf::SingularField<::std::string::String>,
    allow_html: ::std::option::Option<bool>,
    message_length: ::std::option::Option<u32>,
    image_message_length: ::std::option::Option<u32>,
    max_users: ::std::option::Option<u32>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for ServerConfig {}

impl ServerConfig {
    pub fn new() -> ServerConfig {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static ServerConfig {
        static mut instance: ::protobuf::lazy::Lazy<ServerConfig> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ServerConfig,
        };
        unsafe {
            instance.get(ServerConfig::new)
        }
    }

    // optional uint32 max_bandwidth = 1;

    pub fn clear_max_bandwidth(&mut self) {
        self.max_bandwidth = ::std::option::Option::None;
    }

    pub fn has_max_bandwidth(&self) -> bool {
        self.max_bandwidth.is_some()
    }

    // Param is passed by value, moved
    pub fn set_max_bandwidth(&mut self, v: u32) {
        self.max_bandwidth = ::std::option::Option::Some(v);
    }

    pub fn get_max_bandwidth(&self) -> u32 {
        self.max_bandwidth.unwrap_or(0)
    }

    fn get_max_bandwidth_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.max_bandwidth
    }

    fn mut_max_bandwidth_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.max_bandwidth
    }

    // optional string welcome_text = 2;

    pub fn clear_welcome_text(&mut self) {
        self.welcome_text.clear();
    }

    pub fn has_welcome_text(&self) -> bool {
        self.welcome_text.is_some()
    }

    // Param is passed by value, moved
    pub fn set_welcome_text(&mut self, v: ::std::string::String) {
        self.welcome_text = ::protobuf::SingularField::some(v);
    }

    // Mutable pointer to the field.
    // If field is not initialized, it is initialized with default value first.
    pub fn mut_welcome_text(&mut self) -> &mut ::std::string::String {
        if self.welcome_text.is_none() {
            self.welcome_text.set_default();
        }
        self.welcome_text.as_mut().unwrap()
    }

    // Take field
    pub fn take_welcome_text(&mut self) -> ::std::string::String {
        self.welcome_text.take().unwrap_or_else(|| ::std::string::String::new())
    }

    pub fn get_welcome_text(&self) -> &str {
        match self.welcome_text.as_ref() {
            Some(v) => &v,
            None => "",
        }
    }

    fn get_welcome_text_for_reflect(&self) -> &::protobuf::SingularField<::std::string::String> {
        &self.welcome_text
    }

    fn mut_welcome_text_for_reflect(&mut self) -> &mut ::protobuf::SingularField<::std::string::String> {
        &mut self.welcome_text
    }

    // optional bool allow_html = 3;

    pub fn clear_allow_html(&mut self) {
        self.allow_html = ::std::option::Option::None;
    }

    pub fn has_allow_html(&self) -> bool {
        self.allow_html.is_some()
    }

    // Param is passed by value, moved
    pub fn set_allow_html(&mut self, v: bool) {
        self.allow_html = ::std::option::Option::Some(v);
    }

    pub fn get_allow_html(&self) -> bool {
        self.allow_html.unwrap_or(false)
    }

    fn get_allow_html_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.allow_html
    }

    fn mut_allow_html_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.allow_html
    }

    // optional uint32 message_length = 4;

    pub fn clear_message_length(&mut self) {
        self.message_length = ::std::option::Option::None;
    }

    pub fn has_message_length(&self) -> bool {
        self.message_length.is_some()
    }

    // Param is passed by value, moved
    pub fn set_message_length(&mut self, v: u32) {
        self.message_length = ::std::option::Option::Some(v);
    }

    pub fn get_message_length(&self) -> u32 {
        self.message_length.unwrap_or(0)
    }

    fn get_message_length_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.message_length
    }

    fn mut_message_length_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.message_length
    }

    // optional uint32 image_message_length = 5;

    pub fn clear_image_message_length(&mut self) {
        self.image_message_length = ::std::option::Option::None;
    }

    pub fn has_image_message_length(&self) -> bool {
        self.image_message_length.is_some()
    }

    // Param is passed by value, moved
    pub fn set_image_message_length(&mut self, v: u32) {
        self.image_message_length = ::std::option::Option::Some(v);
    }

    pub fn get_image_message_length(&self) -> u32 {
        self.image_message_length.unwrap_or(0)
    }

    fn get_image_message_length_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.image_message_length
    }

    fn mut_image_message_length_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.image_message_length
    }

    // optional uint32 max_users = 6;

    pub fn clear_max_users(&mut self) {
        self.max_users = ::std::option::Option::None;
    }

    pub fn has_max_users(&self) -> bool {
        self.max_users.is_some()
    }

    // Param is passed by value, moved
    pub fn set_max_users(&mut self, v: u32) {
        self.max_users = ::std::option::Option::Some(v);
    }

    pub fn get_max_users(&self) -> u32 {
        self.max_users.unwrap_or(0)
    }

    fn get_max_users_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.max_users
    }

    fn mut_max_users_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.max_users
    }
}

impl ::protobuf::Message for ServerConfig {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.max_bandwidth = ::std::option::Option::Some(tmp);
                },
                2 => {
                    ::protobuf::rt::read_singular_string_into(wire_type, is, &mut self.welcome_text)?;
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.allow_html = ::std::option::Option::Some(tmp);
                },
                4 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.message_length = ::std::option::Option::Some(tmp);
                },
                5 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.image_message_length = ::std::option::Option::Some(tmp);
                },
                6 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.max_users = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.max_bandwidth {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(ref v) = self.welcome_text.as_ref() {
            my_size += ::protobuf::rt::string_size(2, &v);
        }
        if let Some(v) = self.allow_html {
            my_size += 2;
        }
        if let Some(v) = self.message_length {
            my_size += ::protobuf::rt::value_size(4, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.image_message_length {
            my_size += ::protobuf::rt::value_size(5, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.max_users {
            my_size += ::protobuf::rt::value_size(6, v, ::protobuf::wire_format::WireTypeVarint);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.max_bandwidth {
            os.write_uint32(1, v)?;
        }
        if let Some(ref v) = self.welcome_text.as_ref() {
            os.write_string(2, &v)?;
        }
        if let Some(v) = self.allow_html {
            os.write_bool(3, v)?;
        }
        if let Some(v) = self.message_length {
            os.write_uint32(4, v)?;
        }
        if let Some(v) = self.image_message_length {
            os.write_uint32(5, v)?;
        }
        if let Some(v) = self.max_users {
            os.write_uint32(6, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for ServerConfig {
    fn new() -> ServerConfig {
        ServerConfig::new()
    }

    fn descriptor_static(_: ::std::option::Option<ServerConfig>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "max_bandwidth",
                    ServerConfig::get_max_bandwidth_for_reflect,
                    ServerConfig::mut_max_bandwidth_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_singular_field_accessor::<_, ::protobuf::types::ProtobufTypeString>(
                    "welcome_text",
                    ServerConfig::get_welcome_text_for_reflect,
                    ServerConfig::mut_welcome_text_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "allow_html",
                    ServerConfig::get_allow_html_for_reflect,
                    ServerConfig::mut_allow_html_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "message_length",
                    ServerConfig::get_message_length_for_reflect,
                    ServerConfig::mut_message_length_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "image_message_length",
                    ServerConfig::get_image_message_length_for_reflect,
                    ServerConfig::mut_image_message_length_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "max_users",
                    ServerConfig::get_max_users_for_reflect,
                    ServerConfig::mut_max_users_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<ServerConfig>(
                    "ServerConfig",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for ServerConfig {
    fn clear(&mut self) {
        self.clear_max_bandwidth();
        self.clear_welcome_text();
        self.clear_allow_html();
        self.clear_message_length();
        self.clear_image_message_length();
        self.clear_max_users();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for ServerConfig {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

#[derive(PartialEq,Clone,Default)]
pub struct SuggestConfig {
    // message fields
    version: ::std::option::Option<u32>,
    positional: ::std::option::Option<bool>,
    push_to_talk: ::std::option::Option<bool>,
    // special fields
    unknown_fields: ::protobuf::UnknownFields,
    cached_size: ::protobuf::CachedSize,
}

// see codegen.rs for the explanation why impl Sync explicitly
unsafe impl ::std::marker::Sync for SuggestConfig {}

impl SuggestConfig {
    pub fn new() -> SuggestConfig {
        ::std::default::Default::default()
    }

    pub fn default_instance() -> &'static SuggestConfig {
        static mut instance: ::protobuf::lazy::Lazy<SuggestConfig> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const SuggestConfig,
        };
        unsafe {
            instance.get(SuggestConfig::new)
        }
    }

    // optional uint32 version = 1;

    pub fn clear_version(&mut self) {
        self.version = ::std::option::Option::None;
    }

    pub fn has_version(&self) -> bool {
        self.version.is_some()
    }

    // Param is passed by value, moved
    pub fn set_version(&mut self, v: u32) {
        self.version = ::std::option::Option::Some(v);
    }

    pub fn get_version(&self) -> u32 {
        self.version.unwrap_or(0)
    }

    fn get_version_for_reflect(&self) -> &::std::option::Option<u32> {
        &self.version
    }

    fn mut_version_for_reflect(&mut self) -> &mut ::std::option::Option<u32> {
        &mut self.version
    }

    // optional bool positional = 2;

    pub fn clear_positional(&mut self) {
        self.positional = ::std::option::Option::None;
    }

    pub fn has_positional(&self) -> bool {
        self.positional.is_some()
    }

    // Param is passed by value, moved
    pub fn set_positional(&mut self, v: bool) {
        self.positional = ::std::option::Option::Some(v);
    }

    pub fn get_positional(&self) -> bool {
        self.positional.unwrap_or(false)
    }

    fn get_positional_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.positional
    }

    fn mut_positional_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.positional
    }

    // optional bool push_to_talk = 3;

    pub fn clear_push_to_talk(&mut self) {
        self.push_to_talk = ::std::option::Option::None;
    }

    pub fn has_push_to_talk(&self) -> bool {
        self.push_to_talk.is_some()
    }

    // Param is passed by value, moved
    pub fn set_push_to_talk(&mut self, v: bool) {
        self.push_to_talk = ::std::option::Option::Some(v);
    }

    pub fn get_push_to_talk(&self) -> bool {
        self.push_to_talk.unwrap_or(false)
    }

    fn get_push_to_talk_for_reflect(&self) -> &::std::option::Option<bool> {
        &self.push_to_talk
    }

    fn mut_push_to_talk_for_reflect(&mut self) -> &mut ::std::option::Option<bool> {
        &mut self.push_to_talk
    }
}

impl ::protobuf::Message for SuggestConfig {
    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream) -> ::protobuf::ProtobufResult<()> {
        while !is.eof()? {
            let (field_number, wire_type) = is.read_tag_unpack()?;
            match field_number {
                1 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_uint32()?;
                    self.version = ::std::option::Option::Some(tmp);
                },
                2 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.positional = ::std::option::Option::Some(tmp);
                },
                3 => {
                    if wire_type != ::protobuf::wire_format::WireTypeVarint {
                        return ::std::result::Result::Err(::protobuf::rt::unexpected_wire_type(wire_type));
                    }
                    let tmp = is.read_bool()?;
                    self.push_to_talk = ::std::option::Option::Some(tmp);
                },
                _ => {
                    ::protobuf::rt::read_unknown_or_skip_group(field_number, wire_type, is, self.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u32 {
        let mut my_size = 0;
        if let Some(v) = self.version {
            my_size += ::protobuf::rt::value_size(1, v, ::protobuf::wire_format::WireTypeVarint);
        }
        if let Some(v) = self.positional {
            my_size += 2;
        }
        if let Some(v) = self.push_to_talk {
            my_size += 2;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.get_unknown_fields());
        self.cached_size.set(my_size);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream) -> ::protobuf::ProtobufResult<()> {
        if let Some(v) = self.version {
            os.write_uint32(1, v)?;
        }
        if let Some(v) = self.positional {
            os.write_bool(2, v)?;
        }
        if let Some(v) = self.push_to_talk {
            os.write_bool(3, v)?;
        }
        os.write_unknown_fields(self.get_unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn get_cached_size(&self) -> u32 {
        self.cached_size.get()
    }

    fn get_unknown_fields(&self) -> &::protobuf::UnknownFields {
        &self.unknown_fields
    }

    fn mut_unknown_fields(&mut self) -> &mut ::protobuf::UnknownFields {
        &mut self.unknown_fields
    }

    fn as_any(&self) -> &::std::any::Any {
        self as &::std::any::Any
    }
    fn as_any_mut(&mut self) -> &mut ::std::any::Any {
        self as &mut ::std::any::Any
    }
    fn into_any(self: Box<Self>) -> ::std::boxed::Box<::std::any::Any> {
        self
    }

    fn descriptor(&self) -> &'static ::protobuf::reflect::MessageDescriptor {
        ::protobuf::MessageStatic::descriptor_static(None::<Self>)
    }
}

impl ::protobuf::MessageStatic for SuggestConfig {
    fn new() -> SuggestConfig {
        SuggestConfig::new()
    }

    fn descriptor_static(_: ::std::option::Option<SuggestConfig>) -> &'static ::protobuf::reflect::MessageDescriptor {
        static mut descriptor: ::protobuf::lazy::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::lazy::Lazy {
            lock: ::protobuf::lazy::ONCE_INIT,
            ptr: 0 as *const ::protobuf::reflect::MessageDescriptor,
        };
        unsafe {
            descriptor.get(|| {
                let mut fields = ::std::vec::Vec::new();
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeUint32>(
                    "version",
                    SuggestConfig::get_version_for_reflect,
                    SuggestConfig::mut_version_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "positional",
                    SuggestConfig::get_positional_for_reflect,
                    SuggestConfig::mut_positional_for_reflect,
                ));
                fields.push(::protobuf::reflect::accessor::make_option_accessor::<_, ::protobuf::types::ProtobufTypeBool>(
                    "push_to_talk",
                    SuggestConfig::get_push_to_talk_for_reflect,
                    SuggestConfig::mut_push_to_talk_for_reflect,
                ));
                ::protobuf::reflect::MessageDescriptor::new::<SuggestConfig>(
                    "SuggestConfig",
                    fields,
                    file_descriptor_proto()
                )
            })
        }
    }
}

impl ::protobuf::Clear for SuggestConfig {
    fn clear(&mut self) {
        self.clear_version();
        self.clear_positional();
        self.clear_push_to_talk();
        self.unknown_fields.clear();
    }
}

impl ::std::fmt::Debug for SuggestConfig {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for SuggestConfig {
    fn as_ref(&self) -> ::protobuf::reflect::ProtobufValueRef {
        ::protobuf::reflect::ProtobufValueRef::Message(self)
    }
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\x0cMumble.proto\x12\x0bMumbleProto\"l\n\x07Version\x12\x18\n\x07versi\
    on\x18\x01\x20\x01(\rR\x07version\x12\x18\n\x07release\x18\x02\x20\x01(\
    \tR\x07release\x12\x0e\n\x02os\x18\x03\x20\x01(\tR\x02os\x12\x1d\n\nos_v\
    ersion\x18\x04\x20\x01(\tR\tosVersion\"#\n\tUDPTunnel\x12\x16\n\x06packe\
    t\x18\x01\x20\x02(\x0cR\x06packet\"\x9e\x01\n\x0cAuthenticate\x12\x1a\n\
    \x08username\x18\x01\x20\x01(\tR\x08username\x12\x1a\n\x08password\x18\
    \x02\x20\x01(\tR\x08password\x12\x16\n\x06tokens\x18\x03\x20\x03(\tR\x06\
    tokens\x12#\n\rcelt_versions\x18\x04\x20\x03(\x05R\x0cceltVersions\x12\
    \x19\n\x04opus\x18\x05\x20\x01(\x08:\x05falseR\x04opus\"\xc2\x02\n\x04Pi\
    ng\x12\x1c\n\ttimestamp\x18\x01\x20\x01(\x04R\ttimestamp\x12\x12\n\x04go\
    od\x18\x02\x20\x01(\rR\x04good\x12\x12\n\x04late\x18\x03\x20\x01(\rR\x04\
    late\x12\x12\n\x04lost\x18\x04\x20\x01(\rR\x04lost\x12\x16\n\x06resync\
    \x18\x05\x20\x01(\rR\x06resync\x12\x1f\n\x0budp_packets\x18\x06\x20\x01(\
    \rR\nudpPackets\x12\x1f\n\x0btcp_packets\x18\x07\x20\x01(\rR\ntcpPackets\
    \x12\x20\n\x0cudp_ping_avg\x18\x08\x20\x01(\x02R\nudpPingAvg\x12\x20\n\
    \x0cudp_ping_var\x18\t\x20\x01(\x02R\nudpPingVar\x12\x20\n\x0ctcp_ping_a\
    vg\x18\n\x20\x01(\x02R\ntcpPingAvg\x12\x20\n\x0ctcp_ping_var\x18\x0b\x20\
    \x01(\x02R\ntcpPingVar\"\x85\x02\n\x06Reject\x122\n\x04type\x18\x01\x20\
    \x01(\x0e2\x1e.MumbleProto.Reject.RejectTypeR\x04type\x12\x16\n\x06reaso\
    n\x18\x02\x20\x01(\tR\x06reason\"\xae\x01\n\nRejectType\x12\x08\n\x04Non\
    e\x10\0\x12\x10\n\x0cWrongVersion\x10\x01\x12\x13\n\x0fInvalidUsername\
    \x10\x02\x12\x0f\n\x0bWrongUserPW\x10\x03\x12\x11\n\rWrongServerPW\x10\
    \x04\x12\x11\n\rUsernameInUse\x10\x05\x12\x0e\n\nServerFull\x10\x06\x12\
    \x11\n\rNoCertificate\x10\x07\x12\x15\n\x11AuthenticatorFail\x10\x08\"\
    \x90\x01\n\nServerSync\x12\x18\n\x07session\x18\x01\x20\x01(\rR\x07sessi\
    on\x12#\n\rmax_bandwidth\x18\x02\x20\x01(\rR\x0cmaxBandwidth\x12!\n\x0cw\
    elcome_text\x18\x03\x20\x01(\tR\x0bwelcomeText\x12\x20\n\x0bpermissions\
    \x18\x04\x20\x01(\x04R\x0bpermissions\".\n\rChannelRemove\x12\x1d\n\ncha\
    nnel_id\x18\x01\x20\x02(\rR\tchannelId\"\xdd\x02\n\x0cChannelState\x12\
    \x1d\n\nchannel_id\x18\x01\x20\x01(\rR\tchannelId\x12\x16\n\x06parent\
    \x18\x02\x20\x01(\rR\x06parent\x12\x12\n\x04name\x18\x03\x20\x01(\tR\x04\
    name\x12\x14\n\x05links\x18\x04\x20\x03(\rR\x05links\x12\x20\n\x0bdescri\
    ption\x18\x05\x20\x01(\tR\x0bdescription\x12\x1b\n\tlinks_add\x18\x06\
    \x20\x03(\rR\x08linksAdd\x12!\n\x0clinks_remove\x18\x07\x20\x03(\rR\x0bl\
    inksRemove\x12#\n\ttemporary\x18\x08\x20\x01(\x08:\x05falseR\ttemporary\
    \x12\x1d\n\x08position\x18\t\x20\x01(\x05:\x010R\x08position\x12)\n\x10d\
    escription_hash\x18\n\x20\x01(\x0cR\x0fdescriptionHash\x12\x1b\n\tmax_us\
    ers\x18\x0b\x20\x01(\rR\x08maxUsers\"f\n\nUserRemove\x12\x18\n\x07sessio\
    n\x18\x01\x20\x02(\rR\x07session\x12\x14\n\x05actor\x18\x02\x20\x01(\rR\
    \x05actor\x12\x16\n\x06reason\x18\x03\x20\x01(\tR\x06reason\x12\x10\n\
    \x03ban\x18\x04\x20\x01(\x08R\x03ban\"\xac\x04\n\tUserState\x12\x18\n\
    \x07session\x18\x01\x20\x01(\rR\x07session\x12\x14\n\x05actor\x18\x02\
    \x20\x01(\rR\x05actor\x12\x12\n\x04name\x18\x03\x20\x01(\tR\x04name\x12\
    \x17\n\x07user_id\x18\x04\x20\x01(\rR\x06userId\x12\x1d\n\nchannel_id\
    \x18\x05\x20\x01(\rR\tchannelId\x12\x12\n\x04mute\x18\x06\x20\x01(\x08R\
    \x04mute\x12\x12\n\x04deaf\x18\x07\x20\x01(\x08R\x04deaf\x12\x1a\n\x08su\
    ppress\x18\x08\x20\x01(\x08R\x08suppress\x12\x1b\n\tself_mute\x18\t\x20\
    \x01(\x08R\x08selfMute\x12\x1b\n\tself_deaf\x18\n\x20\x01(\x08R\x08selfD\
    eaf\x12\x18\n\x07texture\x18\x0b\x20\x01(\x0cR\x07texture\x12%\n\x0eplug\
    in_context\x18\x0c\x20\x01(\x0cR\rpluginContext\x12'\n\x0fplugin_identit\
    y\x18\r\x20\x01(\tR\x0epluginIdentity\x12\x18\n\x07comment\x18\x0e\x20\
    \x01(\tR\x07comment\x12\x12\n\x04hash\x18\x0f\x20\x01(\tR\x04hash\x12!\n\
    \x0ccomment_hash\x18\x10\x20\x01(\x0cR\x0bcommentHash\x12!\n\x0ctexture_\
    hash\x18\x11\x20\x01(\x0cR\x0btextureHash\x12)\n\x10priority_speaker\x18\
    \x12\x20\x01(\x08R\x0fprioritySpeaker\x12\x1c\n\trecording\x18\x13\x20\
    \x01(\x08R\trecording\"\x86\x02\n\x07BanList\x121\n\x04bans\x18\x01\x20\
    \x03(\x0b2\x1d.MumbleProto.BanList.BanEntryR\x04bans\x12\x1b\n\x05query\
    \x18\x02\x20\x01(\x08:\x05falseR\x05query\x1a\xaa\x01\n\x08BanEntry\x12\
    \x18\n\x07address\x18\x01\x20\x02(\x0cR\x07address\x12\x12\n\x04mask\x18\
    \x02\x20\x02(\rR\x04mask\x12\x12\n\x04name\x18\x03\x20\x01(\tR\x04name\
    \x12\x12\n\x04hash\x18\x04\x20\x01(\tR\x04hash\x12\x16\n\x06reason\x18\
    \x05\x20\x01(\tR\x06reason\x12\x14\n\x05start\x18\x06\x20\x01(\tR\x05sta\
    rt\x12\x1a\n\x08duration\x18\x07\x20\x01(\rR\x08duration\"\x8f\x01\n\x0b\
    TextMessage\x12\x14\n\x05actor\x18\x01\x20\x01(\rR\x05actor\x12\x18\n\
    \x07session\x18\x02\x20\x03(\rR\x07session\x12\x1d\n\nchannel_id\x18\x03\
    \x20\x03(\rR\tchannelId\x12\x17\n\x07tree_id\x18\x04\x20\x03(\rR\x06tree\
    Id\x12\x18\n\x07message\x18\x05\x20\x02(\tR\x07message\"\x93\x03\n\x10Pe\
    rmissionDenied\x12\x1e\n\npermission\x18\x01\x20\x01(\rR\npermission\x12\
    \x1d\n\nchannel_id\x18\x02\x20\x01(\rR\tchannelId\x12\x18\n\x07session\
    \x18\x03\x20\x01(\rR\x07session\x12\x16\n\x06reason\x18\x04\x20\x01(\tR\
    \x06reason\x12:\n\x04type\x18\x05\x20\x01(\x0e2&.MumbleProto.PermissionD\
    enied.DenyTypeR\x04type\x12\x12\n\x04name\x18\x06\x20\x01(\tR\x04name\"\
    \xbd\x01\n\x08DenyType\x12\x08\n\x04Text\x10\0\x12\x0e\n\nPermission\x10\
    \x01\x12\r\n\tSuperUser\x10\x02\x12\x0f\n\x0bChannelName\x10\x03\x12\x0f\
    \n\x0bTextTooLong\x10\x04\x12\x07\n\x03H9K\x10\x05\x12\x14\n\x10Temporar\
    yChannel\x10\x06\x12\x16\n\x12MissingCertificate\x10\x07\x12\x0c\n\x08Us\
    erName\x10\x08\x12\x0f\n\x0bChannelFull\x10\t\x12\x10\n\x0cNestingLimit\
    \x10\n\"\x84\x05\n\x03ACL\x12\x1d\n\nchannel_id\x18\x01\x20\x02(\rR\tcha\
    nnelId\x12'\n\x0cinherit_acls\x18\x02\x20\x01(\x08:\x04trueR\x0binheritA\
    cls\x122\n\x06groups\x18\x03\x20\x03(\x0b2\x1a.MumbleProto.ACL.ChanGroup\
    R\x06groups\x12,\n\x04acls\x18\x04\x20\x03(\x0b2\x18.MumbleProto.ACL.Cha\
    nACLR\x04acls\x12\x1b\n\x05query\x18\x05\x20\x01(\x08:\x05falseR\x05quer\
    y\x1a\xe2\x01\n\tChanGroup\x12\x12\n\x04name\x18\x01\x20\x02(\tR\x04name\
    \x12\"\n\tinherited\x18\x02\x20\x01(\x08:\x04trueR\tinherited\x12\x1e\n\
    \x07inherit\x18\x03\x20\x01(\x08:\x04trueR\x07inherit\x12&\n\x0binherita\
    ble\x18\x04\x20\x01(\x08:\x04trueR\x0binheritable\x12\x10\n\x03add\x18\
    \x05\x20\x03(\rR\x03add\x12\x16\n\x06remove\x18\x06\x20\x03(\rR\x06remov\
    e\x12+\n\x11inherited_members\x18\x07\x20\x03(\rR\x10inheritedMembers\
    \x1a\xd0\x01\n\x07ChanACL\x12#\n\napply_here\x18\x01\x20\x01(\x08:\x04tr\
    ueR\tapplyHere\x12#\n\napply_subs\x18\x02\x20\x01(\x08:\x04trueR\tapplyS\
    ubs\x12\"\n\tinherited\x18\x03\x20\x01(\x08:\x04trueR\tinherited\x12\x17\
    \n\x07user_id\x18\x04\x20\x01(\rR\x06userId\x12\x14\n\x05group\x18\x05\
    \x20\x01(\tR\x05group\x12\x14\n\x05grant\x18\x06\x20\x01(\rR\x05grant\
    \x12\x12\n\x04deny\x18\x07\x20\x01(\rR\x04deny\"4\n\nQueryUsers\x12\x10\
    \n\x03ids\x18\x01\x20\x03(\rR\x03ids\x12\x14\n\x05names\x18\x02\x20\x03(\
    \tR\x05names\"d\n\nCryptSetup\x12\x10\n\x03key\x18\x01\x20\x01(\x0cR\x03\
    key\x12!\n\x0cclient_nonce\x18\x02\x20\x01(\x0cR\x0bclientNonce\x12!\n\
    \x0cserver_nonce\x18\x03\x20\x01(\x0cR\x0bserverNonce\"\xf5\x01\n\x13Con\
    textActionModify\x12\x16\n\x06action\x18\x01\x20\x02(\tR\x06action\x12\
    \x12\n\x04text\x18\x02\x20\x01(\tR\x04text\x12\x18\n\x07context\x18\x03\
    \x20\x01(\rR\x07context\x12H\n\toperation\x18\x04\x20\x01(\x0e2*.MumbleP\
    roto.ContextActionModify.OperationR\toperation\",\n\x07Context\x12\n\n\
    \x06Server\x10\x01\x12\x0b\n\x07Channel\x10\x02\x12\x08\n\x04User\x10\
    \x04\"\x20\n\tOperation\x12\x07\n\x03Add\x10\0\x12\n\n\x06Remove\x10\x01\
    \"`\n\rContextAction\x12\x18\n\x07session\x18\x01\x20\x01(\rR\x07session\
    \x12\x1d\n\nchannel_id\x18\x02\x20\x01(\rR\tchannelId\x12\x16\n\x06actio\
    n\x18\x03\x20\x02(\tR\x06action\"\xb1\x01\n\x08UserList\x120\n\x05users\
    \x18\x01\x20\x03(\x0b2\x1a.MumbleProto.UserList.UserR\x05users\x1as\n\
    \x04User\x12\x17\n\x07user_id\x18\x01\x20\x02(\rR\x06userId\x12\x12\n\
    \x04name\x18\x02\x20\x01(\tR\x04name\x12\x1b\n\tlast_seen\x18\x03\x20\
    \x01(\tR\x08lastSeen\x12!\n\x0clast_channel\x18\x04\x20\x01(\rR\x0blastC\
    hannel\"\xf2\x01\n\x0bVoiceTarget\x12\x0e\n\x02id\x18\x01\x20\x01(\rR\
    \x02id\x129\n\x07targets\x18\x02\x20\x03(\x0b2\x1f.MumbleProto.VoiceTarg\
    et.TargetR\x07targets\x1a\x97\x01\n\x06Target\x12\x18\n\x07session\x18\
    \x01\x20\x03(\rR\x07session\x12\x1d\n\nchannel_id\x18\x02\x20\x01(\rR\tc\
    hannelId\x12\x14\n\x05group\x18\x03\x20\x01(\tR\x05group\x12\x1b\n\x05li\
    nks\x18\x04\x20\x01(\x08:\x05falseR\x05links\x12!\n\x08children\x18\x05\
    \x20\x01(\x08:\x05falseR\x08children\"o\n\x0fPermissionQuery\x12\x1d\n\n\
    channel_id\x18\x01\x20\x01(\rR\tchannelId\x12\x20\n\x0bpermissions\x18\
    \x02\x20\x01(\rR\x0bpermissions\x12\x1b\n\x05flush\x18\x03\x20\x01(\x08:\
    \x05falseR\x05flush\"|\n\x0cCodecVersion\x12\x14\n\x05alpha\x18\x01\x20\
    \x02(\x05R\x05alpha\x12\x12\n\x04beta\x18\x02\x20\x02(\x05R\x04beta\x12'\
    \n\x0cprefer_alpha\x18\x03\x20\x02(\x08:\x04trueR\x0bpreferAlpha\x12\x19\
    \n\x04opus\x18\x04\x20\x01(\x08:\x05falseR\x04opus\"\xae\x06\n\tUserStat\
    s\x12\x18\n\x07session\x18\x01\x20\x01(\rR\x07session\x12$\n\nstats_only\
    \x18\x02\x20\x01(\x08:\x05falseR\tstatsOnly\x12\"\n\x0ccertificates\x18\
    \x03\x20\x03(\x0cR\x0ccertificates\x12=\n\x0bfrom_client\x18\x04\x20\x01\
    (\x0b2\x1c.MumbleProto.UserStats.StatsR\nfromClient\x12=\n\x0bfrom_serve\
    r\x18\x05\x20\x01(\x0b2\x1c.MumbleProto.UserStats.StatsR\nfromServer\x12\
    \x1f\n\x0budp_packets\x18\x06\x20\x01(\rR\nudpPackets\x12\x1f\n\x0btcp_p\
    ackets\x18\x07\x20\x01(\rR\ntcpPackets\x12\x20\n\x0cudp_ping_avg\x18\x08\
    \x20\x01(\x02R\nudpPingAvg\x12\x20\n\x0cudp_ping_var\x18\t\x20\x01(\x02R\
    \nudpPingVar\x12\x20\n\x0ctcp_ping_avg\x18\n\x20\x01(\x02R\ntcpPingAvg\
    \x12\x20\n\x0ctcp_ping_var\x18\x0b\x20\x01(\x02R\ntcpPingVar\x12.\n\x07v\
    ersion\x18\x0c\x20\x01(\x0b2\x14.MumbleProto.VersionR\x07version\x12#\n\
    \rcelt_versions\x18\r\x20\x03(\x05R\x0cceltVersions\x12\x18\n\x07address\
    \x18\x0e\x20\x01(\x0cR\x07address\x12\x1c\n\tbandwidth\x18\x0f\x20\x01(\
    \rR\tbandwidth\x12\x1e\n\nonlinesecs\x18\x10\x20\x01(\rR\nonlinesecs\x12\
    \x1a\n\x08idlesecs\x18\x11\x20\x01(\rR\x08idlesecs\x124\n\x12strong_cert\
    ificate\x18\x12\x20\x01(\x08:\x05falseR\x11strongCertificate\x12\x19\n\
    \x04opus\x18\x13\x20\x01(\x08:\x05falseR\x04opus\x1a[\n\x05Stats\x12\x12\
    \n\x04good\x18\x01\x20\x01(\rR\x04good\x12\x12\n\x04late\x18\x02\x20\x01\
    (\rR\x04late\x12\x12\n\x04lost\x18\x03\x20\x01(\rR\x04lost\x12\x16\n\x06\
    resync\x18\x04\x20\x01(\rR\x06resync\"\x90\x01\n\x0bRequestBlob\x12'\n\
    \x0fsession_texture\x18\x01\x20\x03(\rR\x0esessionTexture\x12'\n\x0fsess\
    ion_comment\x18\x02\x20\x03(\rR\x0esessionComment\x12/\n\x13channel_desc\
    ription\x18\x03\x20\x03(\rR\x12channelDescription\"\xeb\x01\n\x0cServerC\
    onfig\x12#\n\rmax_bandwidth\x18\x01\x20\x01(\rR\x0cmaxBandwidth\x12!\n\
    \x0cwelcome_text\x18\x02\x20\x01(\tR\x0bwelcomeText\x12\x1d\n\nallow_htm\
    l\x18\x03\x20\x01(\x08R\tallowHtml\x12%\n\x0emessage_length\x18\x04\x20\
    \x01(\rR\rmessageLength\x120\n\x14image_message_length\x18\x05\x20\x01(\
    \rR\x12imageMessageLength\x12\x1b\n\tmax_users\x18\x06\x20\x01(\rR\x08ma\
    xUsers\"k\n\rSuggestConfig\x12\x18\n\x07version\x18\x01\x20\x01(\rR\x07v\
    ersion\x12\x1e\n\npositional\x18\x02\x20\x01(\x08R\npositional\x12\x20\n\
    \x0cpush_to_talk\x18\x03\x20\x01(\x08R\npushToTalkB\x02H\x01\
";

static mut file_descriptor_proto_lazy: ::protobuf::lazy::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::lazy::Lazy {
    lock: ::protobuf::lazy::ONCE_INIT,
    ptr: 0 as *const ::protobuf::descriptor::FileDescriptorProto,
};

fn parse_descriptor_proto() -> ::protobuf::descriptor::FileDescriptorProto {
    ::protobuf::parse_from_bytes(file_descriptor_proto_data).unwrap()
}

pub fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    unsafe {
        file_descriptor_proto_lazy.get(|| {
            parse_descriptor_proto()
        })
    }
}
