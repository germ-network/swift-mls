/// The namespace for swift-mls.
///
/// Swift does not permit protocols to nest inside a type, so the codec's
/// protocols (``MLSEncodable``, ``MLSDecodable``) are top-level and prefixed
/// while everything else nests here. No target is named `MLS`: a module and a
/// type sharing a name makes `MLS.Foo` ambiguous inside that module.
public enum MLS {}
