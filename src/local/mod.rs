//! The Bridge's private MCP endpoint: the AI app talks to this computer, the number and the
//! text never leave it, and the server only decides whether a message may go out (limits,
//! approval mode) from a keyed tag of the number and the length.

pub mod approvals;
pub mod engine;
pub mod localweb;
pub mod mcp;
pub mod relayweb;
pub mod store;
