import Foundation
import Darwin

/// 与安卓端 IpPacket.kt 对齐的 IPv4 + UDP 报文构造器。
public enum IpPacket {

    private static let idLock = NSLock()
    private static var nextId = 1

    /// 构造 IPv4 + UDP 报文。解码器只读地址/端口/载荷，这里给出合法头即可。
    public static func buildUdp(sourceIp: [UInt8],
                                destinationIp: [UInt8],
                                sourcePort: Int,
                                destinationPort: Int,
                                payload: [UInt8]) -> [UInt8] {
        let total = 20 + 8 + payload.count
        var packet = [UInt8](repeating: 0, count: total)
        packet[0] = 0x45
        packet[1] = 0
        packet[2] = UInt8((total >> 8) & 0xff)
        packet[3] = UInt8(total & 0xff)

        idLock.lock()
        let id = nextId
        nextId = nextId >= 0xffff ? 1 : nextId + 1
        idLock.unlock()

        packet[4] = UInt8((id >> 8) & 0xff)
        packet[5] = UInt8(id & 0xff)
        packet[6] = 0x40
        packet[7] = 0
        packet[8] = 64
        packet[9] = 17
        packet[10] = 0
        packet[11] = 0
        if sourceIp.count >= 4 {
            packet.replaceSubrange(12..<16, with: sourceIp[0..<4])
        }
        if destinationIp.count >= 4 {
            packet.replaceSubrange(16..<20, with: destinationIp[0..<4])
        }
        let checksum = ipChecksum(packet, offset: 0, length: 20)
        packet[10] = UInt8((checksum >> 8) & 0xff)
        packet[11] = UInt8(checksum & 0xff)

        packet[20] = UInt8((sourcePort >> 8) & 0xff)
        packet[21] = UInt8(sourcePort & 0xff)
        packet[22] = UInt8((destinationPort >> 8) & 0xff)
        packet[23] = UInt8(destinationPort & 0xff)
        let udpLength = 8 + payload.count
        packet[24] = UInt8((udpLength >> 8) & 0xff)
        packet[25] = UInt8(udpLength & 0xff)
        packet[26] = 0
        packet[27] = 0
        if !payload.isEmpty {
            packet.replaceSubrange(28..<(28 + payload.count), with: payload)
        }
        return packet
    }

    private static func ipChecksum(_ data: [UInt8], offset: Int, length: Int) -> Int {
        var sum = 0
        var i = offset
        let end = offset + length
        while i + 1 < end {
            sum += (Int(data[i]) << 8) | Int(data[i + 1])
            i += 2
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return (~sum) & 0xffff
    }

    /// 等价于安卓端 `IpPacket.ipv4(address)`：仅 IPv4 返回 4 字节，否则 nil。
    public static func ipv4(_ host: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, host, &addr) == 1 else { return nil }
        var raw = addr
        return withUnsafeBytes(of: &raw) { Array($0) }
    }
}
