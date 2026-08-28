#if os(macOS) || os(Linux)
import Foundation
import GRPCCore
import GRPCNIOTransportHTTP2Posix

/// `mls-interop-server [port]` — the mlswg MLSClient service over
/// `MLS.RFC9420`, for the interop runner. Defaults to :50051.
///
/// Availability-gated to macOS 15 because grpc-swift 2 requires it; the
/// library products keep the package's macOS 14 floor, since nothing but
/// this executable target depends on gRPC.
@available(macOS 15, *)
@main
struct InteropServerMain {
	static func main() async throws {
		let port =
			CommandLine.arguments.count > 1
			? Int(CommandLine.arguments[1]) ?? 50051 : 50051
		let transport = HTTP2ServerTransport.Posix(
			address: .ipv4(host: "127.0.0.1", port: port),
			transportSecurity: .plaintext)
		FileHandle.standardError.write(
			Data("mls-interop-server listening on 127.0.0.1:\(port)\n".utf8))
		// `withGRPCServer` runs the server for the closure's lifetime; the
		// closure must block, not call `serve()` (which would be a second
		// start). Wait for the bind, then sleep until the process is
		// killed by the runner.
		try await withGRPCServer(
			transport: transport, services: [MLSInteropService()]
		) { server in
			_ = try await server.listeningAddress
			try await Task.sleep(for: .seconds(365 * 24 * 60 * 60))
		}
	}
}
#endif
