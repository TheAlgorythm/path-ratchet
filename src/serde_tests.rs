use crate::prelude::*;
use serde_test::{assert_de_tokens_error, assert_tokens, Token};

#[test]
fn test_ser_de_valid_single_path_buf() {
    let valid_folder = SingleComponentPathBuf::new("foo").unwrap();

    assert_tokens(&valid_folder, &[Token::String("foo")]);
}

#[test]
fn test_de_invalid_single_path_buf() {
    assert_de_tokens_error::<SingleComponentPathBuf>(&[Token::String("foo/bar")], &"invalid value: string \"foo/bar\", expected a path with only a single forwarding component");
}

#[test]
fn test_ser_de_valid_single_path() {
    let valid_folder = SingleComponentPath::new("foo").unwrap();

    assert_tokens(&valid_folder, &[Token::BorrowedStr("foo")]);
}

#[test]
fn test_de_invalid_single_path() {
    assert_de_tokens_error::<&SingleComponentPath>(&[Token::BorrowedStr("../foo")], &"invalid value: string \"../foo\", expected a path with only a single forwarding component");
}

#[test]
fn test_ser_de_valid_multi_path_buf() {
    let valid_folder = MultiComponentPathBuf::new("foo/bar").unwrap();

    assert_tokens(&valid_folder, &[Token::String("foo/bar")]);
}

#[test]
fn test_de_invalid_multi_path_buf() {
    assert_de_tokens_error::<MultiComponentPathBuf>(
        &[Token::String("foo/../../bar")],
        &"invalid value: string \"foo/../../bar\", expected a relative, only forwarding, path",
    );
}

#[test]
fn test_ser_de_valid_multi_path() {
    let valid_folder = MultiComponentPath::new("foo/bar").unwrap();

    assert_tokens(&valid_folder, &[Token::BorrowedStr("foo/bar")]);
}

#[test]
fn test_de_invalid_multi_path() {
    assert_de_tokens_error::<&MultiComponentPath>(
        &[Token::BorrowedStr("/foo/bar")],
        &"invalid value: string \"/foo/bar\", expected a relative, only forwarding, path",
    );
}
