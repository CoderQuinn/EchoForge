import DNSClient
import NIO

// Shared test helpers for building/parsing raw DNS packets used across tests.
func makeQueryMessage(domain: String, type: DNSResourceType = .a, id: UInt16 = 1) throws -> Message {
    let allocator = ByteBufferAllocator()
    var buf = allocator.buffer(capacity: 128)
    buf.writeInteger(id, endianness: .big)
    buf.writeInteger(UInt16(0), endianness: .big)
    buf.writeInteger(UInt16(1), endianness: .big)
    buf.writeInteger(UInt16(0), endianness: .big)
    buf.writeInteger(UInt16(0), endianness: .big)
    buf.writeInteger(UInt16(0), endianness: .big)

    for label in domain.split(separator: ".") {
        let bytes = Array(label.utf8)
        buf.writeInteger(UInt8(bytes.count))
        buf.writeBytes(bytes)
    }
    buf.writeInteger(UInt8(0))
    buf.writeInteger(type.rawValue, endianness: .big)
    buf.writeInteger(UInt16(1), endianness: .big)

    return try DNSDecoder.parse(buf)
}

func makeResponseMessage(domain: String, ip: UInt32?, id: UInt16 = 1) throws -> Message {
    let allocator = ByteBufferAllocator()
    var buf = allocator.buffer(capacity: 256)
    buf.writeInteger(id, endianness: .big)
    // set the response + recursion available bits
    buf.writeInteger(UInt16(0x8400), endianness: .big)
    buf.writeInteger(UInt16(1), endianness: .big) // qdcount
    buf.writeInteger(ip != nil ? UInt16(1) : UInt16(0), endianness: .big) // ancount
    buf.writeInteger(UInt16(0), endianness: .big)
    buf.writeInteger(UInt16(0), endianness: .big)

    // question
    for label in domain.split(separator: ".") {
        let bytes = Array(label.utf8)
        buf.writeInteger(UInt8(bytes.count))
        buf.writeBytes(bytes)
    }
    buf.writeInteger(UInt8(0))
    buf.writeInteger(DNSResourceType.a.rawValue, endianness: .big)
    buf.writeInteger(UInt16(1), endianness: .big)

    // answer (if present)
    if let ip = ip {
        // name: pointer to offset 12 (0xC00C)
        buf.writeInteger(UInt16(0xC00C), endianness: .big)
        buf.writeInteger(UInt16(1), endianness: .big) // type A
        buf.writeInteger(UInt16(1), endianness: .big) // class IN
        buf.writeInteger(UInt32(300), endianness: .big) // ttl
        buf.writeInteger(UInt16(4), endianness: .big) // rdlength
        buf.writeInteger(ip, endianness: .big)
    }

    return try DNSDecoder.parse(buf)
}
