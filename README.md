# ssh-packet
[![docs.rs](https://img.shields.io/docsrs/ssh-packet)](https://docs.rs/ssh-packet) [![Crates.io](https://img.shields.io/crates/l/ssh-packet)](https://crates.io/crates/ssh-packet)

Representations of SSH packets interoperable with their binary
wire representation, using [binrw](https://docs.rs/binrw).

This includes a partial implementation of:
- [RFC4250: SSH Protocol Assigned Numbers](https://datatracker.ietf.org/doc/html/rfc4250).
- [RFC4251: SSH Protocol Architecture](https://datatracker.ietf.org/doc/html/rfc4251).
- [RFC4252: SSH Authentication Protocol](https://datatracker.ietf.org/doc/html/rfc4252).
- [RFC4253: SSH Transport Layer Protocol](https://datatracker.ietf.org/doc/html/rfc4253).
- [RFC4254: SSH Connection Protocol](https://datatracker.ietf.org/doc/html/rfc4254).
- [RFC4256: Generic Message Exchange Authentication for SSH](https://datatracker.ietf.org/doc/html/rfc4256).

---

Note: this is currently a draft and shouldn't be used, yet.
