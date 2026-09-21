import Foundation

/// Holds a `CheckedContinuation` so callbacks that arrive on arbitrary threads
/// (XPC reply blocks, `DispatchWorkItem` timeouts) can resume it exactly once.
///
/// It unwraps the `Result` internally and calls `resume(returning:)` /
/// `resume(throwing:)`, which is what keeps Swift 6 happy: `resume(with:)` takes
/// a `sending` parameter, so handing it a task-isolated `Result` is diagnosed as
/// `#SendingRisksDataRace`.
///
/// Moved here verbatim from `SystemProxyService.swift`, where it was
/// file-private, so `PrivilegedCoreService` can use it too.
final class ContinuationBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?

    init(_ continuation: CheckedContinuation<Value, Error>) {
        self.continuation = continuation
    }

    func resume(with result: Result<Value, Error>) {
        self.lock.lock()
        guard let continuation else {
            self.lock.unlock()
            return
        }
        self.continuation = nil
        self.lock.unlock()

        switch result {
        case let .success(value):
            continuation.resume(returning: value)
        case let .failure(error):
            continuation.resume(throwing: error)
        }
    }
}
