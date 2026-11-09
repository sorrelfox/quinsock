//! Authentication method selection and RFC 1929 username/password subnegotiation.

use std::collections::HashMap;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{AuthConfig, AuthMode};
use crate::error::SocksError;
use crate::protocol::handshake::Methods;
use crate::protocol::method;

const SUBNEGOTIATION_VERSION: u8 = 0x01;

pub struct Authenticator {
    required: bool,
    users: HashMap<Box<[u8]>, Box<[u8]>>,
}

impl Authenticator {
    pub fn new(cfg: &AuthConfig) -> Self {
        let users = cfg
            .users
            .iter()
            .map(|u| (u.username.as_bytes().into(), u.password.as_bytes().into()))
            .collect();
        Self {
            required: cfg.mode == AuthMode::Password,
            users,
        }
    }

    /// Picks the method to use from those offered. GSSAPI is never selected.
    pub fn select_method(&self, offered: &Methods) -> u8 {
        let wanted = if self.required {
            method::USER_PASS
        } else {
            method::NO_AUTH
        };
        if offered.contains(wanted) {
            wanted
        } else {
            method::NO_ACCEPTABLE
        }
    }

    /// Runs the subnegotiation for `selected`, if it has one.
    pub async fn authenticate<S>(&self, selected: u8, stream: &mut S) -> Result<(), SocksError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if selected != method::USER_PASS {
            return Ok(());
        }
        let version = stream.read_u8().await?;
        if version != SUBNEGOTIATION_VERSION {
            return Err(SocksError::Malformed(
                "username/password subnegotiation version",
            ));
        }
        let mut user_buf = [0u8; 255];
        let user = read_field(stream, &mut user_buf).await?;
        let mut pass_buf = [0u8; 255];
        let pass = read_field(stream, &mut pass_buf).await?;

        let ok = self.verify(user, pass);
        stream
            .write_all(&[SUBNEGOTIATION_VERSION, if ok { 0x00 } else { 0x01 }])
            .await?;
        // Debug formatting escapes control characters sent by the client.
        let user = String::from_utf8_lossy(user);
        if ok {
            tracing::debug!(?user, "authenticated");
            Ok(())
        } else {
            tracing::debug!(?user, "authentication failed");
            Err(SocksError::AuthFailed)
        }
    }

    fn verify(&self, user: &[u8], pass: &[u8]) -> bool {
        match self.users.get(user) {
            Some(expected) => expected.as_ref().ct_eq(pass).into(),
            None => {
                // Do comparable work for unknown users so timing does not reveal
                // which usernames exist.
                let _ = std::hint::black_box(pass.ct_eq(pass));
                false
            }
        }
    }
}

async fn read_field<'b, R: AsyncRead + Unpin>(
    r: &mut R,
    buf: &'b mut [u8; 255],
) -> Result<&'b [u8], SocksError> {
    let len = usize::from(r.read_u8().await?);
    let field = buf
        .get_mut(..len)
        .ok_or(SocksError::Malformed("field length"))?;
    r.read_exact(field).await?;
    Ok(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::User;
    use crate::protocol::handshake::read_greeting;

    fn password_auth() -> Authenticator {
        Authenticator::new(&AuthConfig {
            mode: AuthMode::Password,
            users: vec![User {
                username: "alice".into(),
                password: "secret".into(),
            }],
        })
    }

    async fn methods(list: &[u8]) -> Methods {
        let mut msg = vec![5, list.len() as u8];
        msg.extend_from_slice(list);
        read_greeting(&mut msg.as_slice()).await.unwrap()
    }

    #[tokio::test]
    async fn method_selection() {
        let none = Authenticator::new(&AuthConfig::default());
        let pass = password_auth();
        assert_eq!(none.select_method(&methods(&[0]).await), method::NO_AUTH);
        assert_eq!(none.select_method(&methods(&[2, 0]).await), method::NO_AUTH);
        assert_eq!(
            none.select_method(&methods(&[2]).await),
            method::NO_ACCEPTABLE
        );
        assert_eq!(
            none.select_method(&methods(&[1]).await),
            method::NO_ACCEPTABLE
        );
        assert_eq!(
            pass.select_method(&methods(&[0, 2]).await),
            method::USER_PASS
        );
        assert_eq!(
            pass.select_method(&methods(&[0]).await),
            method::NO_ACCEPTABLE
        );
        assert_eq!(
            pass.select_method(&methods(&[]).await),
            method::NO_ACCEPTABLE
        );
    }

    async fn run(
        auth: &Authenticator,
        user: &str,
        pass: &str,
    ) -> (Result<(), SocksError>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut msg = vec![1, user.len() as u8];
        msg.extend_from_slice(user.as_bytes());
        msg.push(pass.len() as u8);
        msg.extend_from_slice(pass.as_bytes());
        client.write_all(&msg).await.unwrap();
        let res = auth.authenticate(method::USER_PASS, &mut server).await;
        drop(server);
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        (res, reply)
    }

    #[tokio::test]
    async fn rfc1929_subnegotiation() {
        let auth = password_auth();
        let (res, reply) = run(&auth, "alice", "secret").await;
        assert!(res.is_ok());
        assert_eq!(reply, [1, 0]);

        let (res, reply) = run(&auth, "alice", "wrong").await;
        assert!(matches!(res, Err(SocksError::AuthFailed)));
        assert_eq!(reply, [1, 1]);

        let (res, reply) = run(&auth, "mallory", "secret").await;
        assert!(matches!(res, Err(SocksError::AuthFailed)));
        assert_eq!(reply, [1, 1]);

        let (res, _) = run(&auth, "alice", "").await;
        assert!(matches!(res, Err(SocksError::AuthFailed)));
    }

    #[tokio::test]
    async fn rejects_bad_subnegotiation_version() {
        let auth = password_auth();
        let mut stream = tokio_test_stream(&[5, 1, b'a', 1, b'b']);
        assert!(matches!(
            auth.authenticate(method::USER_PASS, &mut stream).await,
            Err(SocksError::Malformed(_))
        ));
    }

    fn tokio_test_stream(input: &[u8]) -> tokio::io::Join<&[u8], tokio::io::Sink> {
        tokio::io::join(input, tokio::io::sink())
    }
}
